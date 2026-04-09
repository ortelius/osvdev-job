// Ortelius v11 Vulnerability Microservice that handles creating Vulnerability from OSV.dev
// Runs as a cronjob
//
// CRITICAL FIXES APPLIED:
// 1. Restored Robust Materialized Edge logic (release2cve) from working snippet
// 2. Fixed cve2purl Hub population to prevent empty collections
// 3. Permanent Fix for Bad Dates using DATE_ISO8601 and DATE_TIMESTAMP
// 4. Maintained Go-side and AQL version validation
// 5. Normalized all outgoing timestamps to RFC3339 strings for AQL compatibility
// 6. BACKEND CONSISTENCY: Matching validation logic with restapi/modules/releases/handlers.go
// 7. IMPROVED FORMATTING: All AQL queries formatted for maximum readability
package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/ortelius/ortelius/v12/database"
	"github.com/ortelius/ortelius/v12/restapi/modules/lifecycle"
	"github.com/ortelius/ortelius/v12/util"
)

var logger = database.InitLogger()
var dbconn = database.InitializeDatabase()

// ============================================================================
// Main Import Logic
// ============================================================================

func LoadFromOSVDev() {
	baseURL := "https://www.googleapis.com/download/storage/v1/b/osv-vulnerabilities/o/ecosystems.txt?alt=media"

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: false, MinVersion: tls.VersionTLS12},
		MaxIdleConns:    100,
	}
	client := &http.Client{Transport: tr}

	resp, err := client.Get(baseURL)
	if err != nil {
		logger.Sugar().Fatal(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Sugar().Fatalln(err)
	}

	lines := strings.Split(string(body), "\n")
	totalCVEsUpdated := 0

	for _, line := range lines {
		platform := strings.TrimSpace(line)
		if len(platform) == 0 {
			continue
		}

		cveCount := processEcosystem(client, platform)
		totalCVEsUpdated += cveCount
	}

	if totalCVEsUpdated > 0 {
		logger.Sugar().Infof("All ecosystems processed. Total CVEs updated: %d. Running lifecycle tracking...", totalCVEsUpdated)
		if err := updateLifecycleForNewCVEs(totalCVEsUpdated); err != nil {
			logger.Sugar().Warnf("Failed to update lifecycle tracking after CVE updates: %v", err)
		} else {
			logger.Sugar().Infof("Lifecycle tracking update complete")
		}
	} else {
		logger.Sugar().Infof("No CVE updates. Skipping lifecycle tracking.")
	}
}

// ============================================================================
// Ecosystem Processing
// ============================================================================

func processEcosystem(client *http.Client, platform string) int {
	lastRunTime, _ := util.GetLastRun(dbconn, platform)
	urlStr := fmt.Sprintf("https://www.googleapis.com/download/storage/v1/b/osv-vulnerabilities/o/%s%%2Fall.zip?alt=media", url.PathEscape(platform))

	resp, err := client.Get(urlStr)
	if err != nil {
		logger.Sugar().Errorf("Failed to download %s: %v", platform, err)
		return 0
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Sugar().Errorf("Failed to read body for %s: %v", platform, err)
		return 0
	}

	zipReader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		logger.Sugar().Errorf("Failed to open zip reader for %s: %v", platform, err)
		return 0
	}

	var maxSeenTime = lastRunTime
	var cveCount int

	for _, f := range zipReader.File {
		if f.FileInfo().IsDir() || strings.Contains(f.Name, "/") {
			continue
		}

		func() {
			rc, err := f.Open()
			if err != nil {
				return
			}
			defer rc.Close()

			var content map[string]interface{}
			if err := json.NewDecoder(rc).Decode(&content); err != nil {
				return
			}

			modStr, _ := content["modified"].(string)
			if modStr != "" {
				modTime, err := time.Parse(time.RFC3339, modStr)
				if err == nil {
					if modTime.After(maxSeenTime) {
						maxSeenTime = modTime
					}
					if !modTime.After(lastRunTime) {
						return
					}
				}
			}

			// Add CVSS scores
			util.AddCVSSScoresToContent(content)

			wasUpdated, _ := newVuln(content)
			if wasUpdated {
				cveCount++
				if cveKey, ok := content["_key"].(string); ok {
					if err := updateReleaseEdgesForCVE(context.Background(), cveKey); err != nil {
						logger.Sugar().Errorf("Failed to update release edges for CVE %s: %v", cveKey, err)
					}
				}
			}
		}()
	}

	if cveCount > 0 {
		if maxSeenTime.IsZero() {
			maxSeenTime = time.Now().UTC()
		}
		logger.Sugar().Infof("Ecosystem: %s | New CVEs: %d | Updating high water mark to %s", platform, cveCount, maxSeenTime.Format(time.RFC3339))
		util.SaveLastRun(dbconn, platform, maxSeenTime)
	} else {
		logger.Sugar().Infof("Ecosystem: %s | No new CVEs found", platform)
	}

	return cveCount
}

// ============================================================================
// CVE Document Processing
// ============================================================================

func newVuln(content map[string]interface{}) (bool, error) {
	var ctx = context.Background()
	id, ok := content["id"].(string)
	if !ok || id == "" {
		return false, nil
	}

	cveKey := util.SanitizeKey(id)
	content["_key"] = cveKey
	content["objtype"] = "CVE"

	// Check if already processed with same modification date
	modDate, _ := content["modified"].(string)
	parameters := map[string]interface{}{"key": cveKey}

	checkModQuery := `
		FOR vuln IN cve 
			FILTER vuln._key == @key 
			RETURN vuln.modified
	`

	cursor, err := dbconn.Database.Query(ctx, checkModQuery, &arangodb.QueryOptions{
		BindVars: parameters,
	})
	if err == nil {
		defer cursor.Close()
		if cursor.HasMore() {
			var existingMod string
			if _, err := cursor.ReadDocument(ctx, &existingMod); err == nil {
				if existingMod == modDate {
					return false, nil // No update needed
				}
			}
		}
	}

	// Skip CVEs without affected packages
	if _, exists := content["affected"]; !exists {
		return false, nil
	}

	// Upsert CVE document
	upsertQuery := `
		UPSERT { _key: @key } 
		INSERT @doc 
		UPDATE @doc 
		IN cve
	`
	bindVars := map[string]interface{}{
		"key": cveKey,
		"doc": content,
	}

	if _, err := dbconn.Database.Query(ctx, upsertQuery, &arangodb.QueryOptions{
		BindVars: bindVars,
	}); err != nil {
		return false, err
	}

	// Populate cve2purl Hub edges
	processEdges(ctx, content)

	return true, nil
}

// ============================================================================
// CVE to PURL Hub Edge Processing
// ============================================================================

func processEdges(ctx context.Context, content map[string]interface{}) error {
	cveID, _ := content["id"].(string)
	cveKey := util.SanitizeKey(cveID)
	cveDocID := "cve/" + cveKey

	affected, ok := content["affected"].([]interface{})
	if !ok || len(affected) == 0 {
		return nil
	}

	for _, affItem := range affected {
		affMap, ok := affItem.(map[string]interface{})
		if !ok {
			continue
		}

		pkgMap, ok := affMap["package"].(map[string]interface{})
		if !ok {
			continue
		}

		// BACKEND CONSISTENCY: Use centralized PURL standardization
		var basePurl string
		if purl, ok := pkgMap["purl"].(string); ok && purl != "" {
			cleaned, err := util.CleanPURL(purl)
			if err != nil {
				continue
			}
			basePurl, err = util.GetStandardBasePURL(cleaned)
			if err != nil {
				continue
			}
		} else {
			ecosystem, _ := pkgMap["ecosystem"].(string)
			namespace, _ := pkgMap["namespace"].(string)
			name, _ := pkgMap["name"].(string)
			if ecosystem == "" || name == "" {
				continue
			}
			basePurl = util.GetBasePURLFromComponents(ecosystem, namespace, name)
		}

		// Create PURL hub node
		purlKey := util.SanitizeKey(basePurl)
		purlNode := map[string]interface{}{
			"_key":    purlKey,
			"purl":    basePurl,
			"objtype": "PURL",
		}

		purlUpsertQuery := `
			UPSERT { _key: @key } 
			INSERT @doc 
			UPDATE {} 
			IN purl
		`
		dbconn.Database.Query(ctx, purlUpsertQuery, &arangodb.QueryOptions{
			BindVars: map[string]interface{}{
				"key": purlKey,
				"doc": purlNode,
			},
		})

		purlDocID := "purl/" + purlKey

		// Process version ranges
		ranges, _ := affMap["ranges"].([]interface{})
		if len(ranges) == 0 {
			continue
		}

		for _, rangeItem := range ranges {
			rangeMap, ok := rangeItem.(map[string]interface{})
			if !ok {
				continue
			}

			rangeType, _ := rangeMap["type"].(string)
			events, _ := rangeMap["events"].([]interface{})

			// Extract version events
			var introduced, fixed, lastAffected string
			for _, eventItem := range events {
				eventMap, ok := eventItem.(map[string]interface{})
				if !ok {
					continue
				}
				if introVal, ok := eventMap["introduced"].(string); ok {
					introduced = introVal
				}
				if fixedVal, ok := eventMap["fixed"].(string); ok {
					fixed = fixedVal
				}
				if laVal, ok := eventMap["last_affected"].(string); ok {
					lastAffected = laVal
				}
			}

			if introduced == "" {
				introduced = "0"
			}

			// Parse semantic versions for fast range checking
			introducedParsed := util.ParseSemanticVersion(introduced)
			fixedParsed := util.ParseSemanticVersion(fixed)
			lastAffectedParsed := util.ParseSemanticVersion(lastAffected)

			// Build edge with version metadata
			edge := map[string]interface{}{
				"_from":         cveDocID,
				"_to":           purlDocID,
				"type":          rangeType,
				"introduced":    introduced,
				"fixed":         fixed,
				"last_affected": lastAffected,
			}

			// Add parsed version components for fast AQL range queries
			if introducedParsed.Major != nil {
				edge["introduced_major"] = *introducedParsed.Major
			}
			if introducedParsed.Minor != nil {
				edge["introduced_minor"] = *introducedParsed.Minor
			}
			if introducedParsed.Patch != nil {
				edge["introduced_patch"] = *introducedParsed.Patch
			}

			if fixedParsed.Major != nil {
				edge["fixed_major"] = *fixedParsed.Major
			}
			if fixedParsed.Minor != nil {
				edge["fixed_minor"] = *fixedParsed.Minor
			}
			if fixedParsed.Patch != nil {
				edge["fixed_patch"] = *fixedParsed.Patch
			}

			if lastAffectedParsed.Major != nil {
				edge["last_affected_major"] = *lastAffectedParsed.Major
			}
			if lastAffectedParsed.Minor != nil {
				edge["last_affected_minor"] = *lastAffectedParsed.Minor
			}
			if lastAffectedParsed.Patch != nil {
				edge["last_affected_patch"] = *lastAffectedParsed.Patch
			}

			// Check if edge already exists
			checkEdgeQuery := `
				FOR e IN cve2purl
					FILTER e._from == @from 
					   AND e._to == @to
					LIMIT 1
					RETURN e
			`
			cursor, err := dbconn.Database.Query(ctx, checkEdgeQuery, &arangodb.QueryOptions{
				BindVars: map[string]interface{}{
					"from": cveDocID,
					"to":   purlDocID,
				},
			})
			if err != nil {
				continue
			}

			exists := cursor.HasMore()
			cursor.Close()

			if !exists {
				_, err = dbconn.Collections["cve2purl"].CreateDocument(ctx, edge)
				if err != nil {
					logger.Sugar().Warnf("Failed to create cve2purl edge from %s to %s: %v", cveDocID, purlDocID, err)
				}
			}
		}
	}

	return nil
}

// ============================================================================
// Release to CVE Materialized Edge Creation
// BACKEND CONSISTENCY: Matches restapi/modules/releases/handlers.go
// ============================================================================

func updateReleaseEdgesForCVE(ctx context.Context, cveKey string) error {
	cveID := "cve/" + cveKey

	// Step 1: Clean up existing edges for this CVE
	cleanupQuery := `
		FOR edge IN release2cve 
			FILTER edge._to == @cveID 
			REMOVE edge IN release2cve
	`
	dbconn.Database.Query(ctx, cleanupQuery, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{
			"cveID": cveID,
		},
	})

	// Step 2: Find all releases that should be linked to this CVE
	// Uses hub-spoke architecture: CVE → PURL ← SBOM ← Release
	// Includes fast-path version range checking using parsed version components
	query := `
		FOR cve IN cve
			FILTER cve._key == @cveKey
			
			// Traverse to PURL hub nodes
			FOR cveEdge IN cve2purl
				FILTER cveEdge._from == cve._id
				
				LET purl = DOCUMENT(cveEdge._to)
				FILTER purl != null
				
				// Traverse to SBOMs that reference this PURL
				FOR sbomEdge IN sbom2purl
					FILTER sbomEdge._to == purl._id
					
					// Fast path: Use parsed version metadata for range checking
					// This avoids expensive ecosystem-specific parsing in AQL
					FILTER (
						// Only use fast path if all version metadata is available
						sbomEdge.version_major != null AND 
						cveEdge.introduced_major != null AND 
						(cveEdge.fixed_major != null OR cveEdge.last_affected_major != null)
					) ? (
						// Version is in affected range
						(
							// Check if version >= introduced
							sbomEdge.version_major > cveEdge.introduced_major OR
							(
								sbomEdge.version_major == cveEdge.introduced_major AND 
								sbomEdge.version_minor > cveEdge.introduced_minor
							) OR
							(
								sbomEdge.version_major == cveEdge.introduced_major AND 
								sbomEdge.version_minor == cveEdge.introduced_minor AND 
								sbomEdge.version_patch >= cveEdge.introduced_patch
							)
						)
						AND
						(
							// Check if version < fixed OR version <= last_affected
							cveEdge.fixed_major != null ? (
								// Check against fixed version
								sbomEdge.version_major < cveEdge.fixed_major OR
								(
									sbomEdge.version_major == cveEdge.fixed_major AND 
									sbomEdge.version_minor < cveEdge.fixed_minor
								) OR
								(
									sbomEdge.version_major == cveEdge.fixed_major AND 
									sbomEdge.version_minor == cveEdge.fixed_minor AND 
									sbomEdge.version_patch < cveEdge.fixed_patch
								)
							) : (
								// Check against last_affected version
								sbomEdge.version_major < cveEdge.last_affected_major OR
								(
									sbomEdge.version_major == cveEdge.last_affected_major AND 
									sbomEdge.version_minor < cveEdge.last_affected_minor
								) OR
								(
									sbomEdge.version_major == cveEdge.last_affected_major AND 
									sbomEdge.version_minor == cveEdge.last_affected_minor AND 
									sbomEdge.version_patch <= cveEdge.last_affected_patch
								)
							)
						)
					) : true  // Fallback: allow through for Go-side validation
					
					// Traverse to releases that use this SBOM
					FOR release IN 1..1 INBOUND sbomEdge._from release2sbom
						RETURN {
							release_id: release._id,
							package_purl_full: sbomEdge.full_purl,
							package_purl_base: purl.purl,
							package_version: sbomEdge.version,
							all_affected: cve.affected,
							needs_validation: sbomEdge.version_major == null OR cveEdge.introduced_major == null
						}
	`

	cursor, err := dbconn.Database.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{
			"cveKey": cveKey,
		},
	})
	if err != nil {
		return err
	}
	defer cursor.Close()

	type Candidate struct {
		ReleaseID       string            `json:"release_id"`
		PackagePurlFull string            `json:"package_purl_full"`
		PackagePurlBase string            `json:"package_purl_base"`
		PackageVersion  string            `json:"package_version"`
		AllAffected     []models.Affected `json:"all_affected"`
		NeedsValidation bool              `json:"needs_validation"`
	}

	var edgesToInsert []map[string]interface{}
	seenInstances := make(map[string]bool)

	// Step 3: Process candidates and validate if needed
	for cursor.HasMore() {
		var cand Candidate
		if _, err := cursor.ReadDocument(ctx, &cand); err != nil {
			continue
		}

		// Deduplication: One edge per (Release, Base PURL) pair
		instanceKey := cand.ReleaseID + ":" + cand.PackagePurlBase
		if seenInstances[instanceKey] {
			continue
		}

		// BACKEND CONSISTENCY: Match validation logic from restapi/modules/releases/handlers.go
		// Perform ecosystem-specific version validation if fast path was unavailable
		if cand.NeedsValidation && len(cand.AllAffected) > 0 {
			matchFound := false

			// Iterate through all affected entries in the CVE
			for _, affected := range cand.AllAffected {
				// Extract PURL from affected entry
				affectedPurl := ""
				if affected.Package.Purl != "" {
					affectedPurl = affected.Package.Purl
				} else {
					// Build PURL from components
					ecosystem := string(affected.Package.Ecosystem)
					namespace := affected.Package.Name

					// Handle scoped packages (e.g., @org/package)
					if strings.Contains(namespace, "/") {
						parts := strings.Split(namespace, "/")
						if len(parts) == 2 {
							namespace = parts[0]
						}
					}

					affectedPurl = util.GetBasePURLFromComponents(ecosystem, namespace, affected.Package.Name)
				}

				// Standardize the affected PURL for comparison
				standardizedAffectedPurl, err := util.GetStandardBasePURL(affectedPurl)
				if err != nil {
					continue
				}

				// Only validate if the base PURLs match
				// This ensures we're checking the correct affected entry
				if standardizedAffectedPurl == cand.PackagePurlBase {
					// Use ecosystem-specific version validation
					if util.IsVersionAffected(cand.PackageVersion, affected) {
						matchFound = true
						break
					}
				}
			}

			// Skip this candidate if validation failed
			if !matchFound {
				continue
			}
		}

		// Mark as processed
		seenInstances[instanceKey] = true

		// Step 4: Create materialized edge
		edgesToInsert = append(edgesToInsert, map[string]interface{}{
			"_from":           cand.ReleaseID,
			"_to":             cveID,
			"type":            "static_analysis",
			"package_purl":    cand.PackagePurlFull,
			"package_base":    cand.PackagePurlBase,
			"package_version": cand.PackageVersion,
			"created_at":      time.Now().UTC().Format(time.RFC3339),
		})
	}

	// Step 5: Batch insert edges
	if len(edgesToInsert) > 0 {
		insertQuery := `
			FOR edge IN @edges 
				INSERT edge INTO release2cve
		`
		_, err := dbconn.Database.Query(ctx, insertQuery, &arangodb.QueryOptions{
			BindVars: map[string]interface{}{
				"edges": edgesToInsert,
			},
		})
		return err
	}

	return nil
}

// ============================================================================
// Lifecycle Tracking Update
// ============================================================================

func updateLifecycleForNewCVEs(_ int) error {
	ctx := context.Background()

	// Get current state of all endpoints with their active releases
	// Uses DATE_ISO8601 for robust parsing of string-based synced_at timestamps
	endpointStateQuery := `
		FOR endpoint IN endpoint
			// Find latest sync event for this endpoint
			LET latestSync = (
				FOR sync IN sync
					FILTER sync.endpoint_name == endpoint.name
					SORT DATE_TIMESTAMP(sync.synced_at) DESC
					LIMIT 1
					RETURN sync
			)[0]
			
			FILTER latestSync != null
			
			// Get all releases at this sync timestamp (current state)
			LET activeReleases = (
				FOR sync IN sync
					FILTER sync.endpoint_name == endpoint.name
					FILTER sync.synced_at == latestSync.synced_at
					RETURN {
						name: sync.release_name,
						version: sync.release_version
					}
			)
			
			RETURN {
				endpoint_name: endpoint.name,
				releases: activeReleases,
				last_sync_time: DATE_ISO8601(latestSync.synced_at)
			}
	`

	cursor, err := dbconn.Database.Query(ctx, endpointStateQuery, nil)
	if err != nil {
		return err
	}
	defer cursor.Close()

	// Process each endpoint
	for cursor.HasMore() {
		var state struct {
			EndpointName string
			Releases     []ReleaseInfo
			LastSyncTime time.Time
		}
		if _, err := cursor.ReadDocument(ctx, &state); err != nil || state.LastSyncTime.IsZero() {
			continue
		}

		// Get all CVEs affecting these releases
		currentCVEs, _ := getCVEsForReleases(ctx, state.Releases)

		// Update lifecycle records for each CVE
		for _, cveInfo := range currentCVEs {
			// Check if CVE was disclosed after deployment
			disclosedAfter := !cveInfo.Published.IsZero() && cveInfo.Published.After(state.LastSyncTime)

			// Create or update lifecycle record
			// The lifecycle package handles normalization of state.LastSyncTime internally
			lifecycle.CreateOrUpdateLifecycleRecord(
				ctx,
				dbconn,
				state.EndpointName,
				cveInfo.ReleaseName,
				cveInfo.ReleaseVersion,
				cveInfo,
				state.LastSyncTime,
				disclosedAfter,
			)
		}
	}

	return nil
}

// ============================================================================
// Helper Types and Functions
// ============================================================================

type ReleaseInfo struct {
	Name    string
	Version string
}

// getCVEsForReleases retrieves all CVEs affecting the given releases
func getCVEsForReleases(ctx context.Context, releases []ReleaseInfo) (map[string]lifecycle.CVEInfo, error) {
	result := make(map[string]lifecycle.CVEInfo)

	for _, rel := range releases {
		// Query CVEs via materialized release2cve edges
		cveQuery := `
			FOR r IN release
				FILTER r.name == @name 
				   AND r.version == @version
				
				// Traverse release2cve materialized edges
				FOR cve, edge IN 1..1 OUTBOUND r release2cve
					RETURN {
						cve_id: cve.id,
						published: cve.published,
						package: edge.package_base,
						severity_rating: cve.database_specific.severity_rating,
						severity_score: cve.database_specific.cvss_base_score
					}
		`

		cursor, _ := dbconn.Database.Query(ctx, cveQuery, &arangodb.QueryOptions{
			BindVars: map[string]interface{}{
				"name":    rel.Name,
				"version": rel.Version,
			},
		})

		for cursor.HasMore() {
			var v struct {
				CveID          string  `json:"cve_id"`
				Published      string  `json:"published"`
				Package        string  `json:"package"`
				SeverityRating string  `json:"severity_rating"`
				SeverityScore  float64 `json:"severity_score"`
			}

			if _, err := cursor.ReadDocument(ctx, &v); err == nil {
				pub, _ := time.Parse(time.RFC3339, v.Published)

				// Create unique key for deduplication
				key := fmt.Sprintf("%s:%s:%s", v.CveID, v.Package, rel.Name)

				result[key] = lifecycle.CVEInfo{
					CVEID:          v.CveID,
					Package:        v.Package,
					SeverityRating: v.SeverityRating,
					SeverityScore:  v.SeverityScore,
					Published:      pub,
					ReleaseName:    rel.Name,
					ReleaseVersion: rel.Version,
				}
			}
		}
		cursor.Close()
	}

	return result, nil
}

// ============================================================================
// Main Entry Point
// ============================================================================

func main() {
	LoadFromOSVDev()
}
