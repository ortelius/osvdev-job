package main

// Incremental OSV sync using <ECOSYSTEM>/modified_id.csv.
//
// Row format (newest first, no header):
//   2026-10-09T17:28:11.349025021Z,CGA-6f8r-jj9x-cgxr
//
// Normal runs read this small CSV and fetch only the changed <ECOSYSTEM>/<ID>.json
// records, instead of downloading the full all.zip (~1 GB for Chainguard).
// all.zip is still used for the first load (no high-water mark) or when the
// backlog is larger than OSV_INCREMENTAL_MAX.
//
// Records are processed oldest-first and the high-water mark is checkpointed
// every checkpointEvery records, and the loop stops on a time budget
// (OSV_ECO_BUDGET / OSV_RUN_BUDGET), so the next run resumes where this one
// stopped instead of restarting the ecosystem from zero.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/ortelius/ortelius/v12/util"
)

const (
	osvObjectURL    = "https://www.googleapis.com/download/storage/v1/b/osv-vulnerabilities/o/%s?alt=media"
	checkpointEvery = 100
)

// If more records than this changed, one zip download is cheaper than N fetches.
var incrementalMax = envInt("OSV_INCREMENTAL_MAX", 2000)

// Time budgets so a run exits cleanly before activeDeadlineSeconds (780s in the
// chart) and one huge ecosystem (e.g. Chainguard) cannot starve the others.
// Keep OSV_RUN_BUDGET comfortably below the Job deadline so lifecycle tracking
// still has time to run after the ecosystem loop.
var (
	ecoBudget = envDuration("OSV_ECO_BUDGET", 5*time.Minute)
	runBudget = envDuration("OSV_RUN_BUDGET", 9*time.Minute)
	runStart  = time.Now()
)

func runBudgetExceeded() bool { return time.Since(runStart) > runBudget }

type changedRec struct {
	id string
	ts time.Time
}

// osvObject builds the media URL for an object under an ecosystem folder.
// PathEscape turns the "/" into %2F and handles names with spaces
// (e.g. "Azure Linux").
func osvObject(platform, name string) string {
	return fmt.Sprintf(osvObjectURL, url.PathEscape(platform+"/"+name))
}

// fetchChanged returns records modified after `since`, oldest first.
// The whole file is scanned rather than stopping at the first old row, so we
// don't depend on the CSV's sort order.
func fetchChanged(client *http.Client, platform string, since time.Time) ([]changedRec, error) {
	body, err := httpGetWithRetry(client, osvObject(platform, "modified_id.csv"), platform+" modified_id.csv")
	if err != nil {
		return nil, err
	}

	var out []changedRec
	for _, line := range strings.Split(string(body), "\n") {
		ts, id, ok := strings.Cut(strings.TrimSpace(line), ",")
		if !ok || id == "" {
			continue
		}
		t, err := time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			continue
		}
		if t.After(since) {
			out = append(out, changedRec{id: id, ts: t})
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i].ts.Before(out[j].ts) })
	return out, nil
}

// processIncremental returns (cveCount, handled). handled=false means the
// caller should fall back to the all.zip path.
func processIncremental(client *http.Client, platform string, lastRun time.Time) (int, bool) {
	start := time.Now()

	changed, err := fetchChanged(client, platform, lastRun)
	if err != nil {
		logger.Sugar().Warnf("Ecosystem: %s | modified_id.csv unavailable, falling back to all.zip: %v", platform, err)
		return 0, false
	}

	if len(changed) == 0 {
		logger.Sugar().Infof("Ecosystem: %s | No new CVEs found | incremental total=%s",
			platform, time.Since(start).Round(time.Millisecond))
		return 0, true
	}

	if len(changed) > incrementalMax {
		logger.Sugar().Warnf("Ecosystem: %s | %d changed records exceeds OSV_INCREMENTAL_MAX=%d, falling back to all.zip",
			platform, len(changed), incrementalMax)
		return 0, false
	}

	logger.Sugar().Infof("Ecosystem: %s | incremental: %d changed records since %s",
		platform, len(changed), lastRun.Format(time.RFC3339Nano))

	cveCount := 0
	var lastOK time.Time // timestamp of the last record fully handled
	var lastSaved time.Time

	save := func() {
		if !lastOK.IsZero() && lastOK.After(lastSaved) {
			util.SaveLastRun(dbconn, platform, lastOK)
			lastSaved = lastOK
		}
	}

	for i, rec := range changed {
		if time.Since(start) > ecoBudget || runBudgetExceeded() {
			logger.Sugar().Infof("Ecosystem: %s | time budget reached at %d/%d, will resume next run",
				platform, i, len(changed))
			break
		}

		raw, err := httpGetWithRetry(client, osvObject(platform, rec.id+".json"), rec.id)
		if err != nil {
			// Stop here: the mark stays at the last good record, so the next
			// tick retries from this one instead of skipping it.
			logger.Sugar().Errorf("Ecosystem: %s | fetch %s failed, stopping this run: %v", platform, rec.id, err)
			break
		}

		var content map[string]interface{}
		if err := json.Unmarshal(raw, &content); err != nil {
			logger.Sugar().Warnf("Ecosystem: %s | %s: bad JSON, skipping: %v", platform, rec.id, err)
		} else if ingestRecord(content) {
			cveCount++
		}

		lastOK = rec.ts

		if (i+1)%checkpointEvery == 0 {
			save()
			logger.Sugar().Infof("Ecosystem: %s | progress %d/%d (CVEs updated: %d) elapsed=%s",
				platform, i+1, len(changed), cveCount, time.Since(start).Round(time.Second))
		}
	}

	save()
	logger.Sugar().Infof("Ecosystem: %s | incremental done | New CVEs: %d of %d changed | total=%s",
		platform, cveCount, len(changed), time.Since(start).Round(time.Millisecond))
	return cveCount, true
}

// ingestRecord is the per-record work shared by the zip and incremental paths.
func ingestRecord(content map[string]interface{}) bool {
	util.AddCVSSScoresToContent(content)

	wasUpdated, _ := newVuln(content)
	if !wasUpdated {
		return false
	}

	if cveKey, ok := content["_key"].(string); ok {
		if err := updateReleaseEdgesForCVE(context.Background(), cveKey); err != nil {
			logger.Sugar().Errorf("Failed to update release edges for CVE %s: %v", cveKey, err)
		}
	}
	return true
}
