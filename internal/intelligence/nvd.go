package intelligence

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"mossward/internal/model"
)

const (
	DefaultNVDURL       = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	defaultNVDPageSize  = 2000
	maxNVDPageSize      = 2000
	defaultHTTPTimeout  = 45 * time.Second
	maxNVDResponseBytes = 64 << 20
	nvdSourceName       = "NVD"
)

type CVEStore interface {
	UpsertCVEs([]model.CVERecord) error
	RecordFeedStart(string, time.Time) error
	RecordFeedResult(string, time.Time, int, string) error
}

type NVDClient struct {
	HTTPClient *http.Client
	BaseURL    string
	APIKey     string
	PageSize   int
	PageDelay  time.Duration
}

func (client NVDClient) Sync(ctx context.Context, store CVEStore, since, until time.Time) (count int, err error) {
	started := time.Now().UTC()
	if err := store.RecordFeedStart(nvdSourceName, started); err != nil {
		return 0, err
	}
	defer func() {
		message := ""
		if err != nil {
			message = err.Error()
		}
		if recordErr := store.RecordFeedResult(nvdSourceName, time.Now().UTC(), count, message); err == nil && recordErr != nil {
			err = recordErr
		}
	}()
	if client.HTTPClient == nil {
		client.HTTPClient = &http.Client{Timeout: defaultHTTPTimeout}
	}
	if client.BaseURL == "" {
		client.BaseURL = DefaultNVDURL
	}
	if client.PageSize < 1 || client.PageSize > maxNVDPageSize {
		client.PageSize = defaultNVDPageSize
	}
	startIndex := 0
	for {
		records, total, fetchErr := client.fetchPage(ctx, since, until, startIndex)
		if fetchErr != nil {
			return count, fetchErr
		}
		if err := store.UpsertCVEs(records); err != nil {
			return count, err
		}
		count += len(records)
		startIndex += len(records)
		if len(records) == 0 || startIndex >= total {
			break
		}
		if client.PageDelay > 0 {
			select {
			case <-ctx.Done():
				return count, ctx.Err()
			case <-time.After(client.PageDelay):
			}
		}
	}
	return count, nil
}

func (client NVDClient) fetchPage(ctx context.Context, since, until time.Time, startIndex int) ([]model.CVERecord, int, error) {
	endpoint, err := client.pageURL(since, until, startIndex)
	if err != nil {
		return nil, 0, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, 0, err
	}
	request.Header.Set("User-Agent", "Mossward-CVE-Sync/1.0")
	if client.APIKey != "" {
		request.Header.Set("apiKey", client.APIKey)
	}
	response, err := client.HTTPClient.Do(request)
	if err != nil {
		return nil, 0, fmt.Errorf("request NVD feed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("NVD feed returned HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxNVDResponseBytes))
	if err != nil {
		return nil, 0, fmt.Errorf("read NVD feed: %w", err)
	}
	return ParseNVD(body)
}

func (client NVDClient) pageURL(since, until time.Time, startIndex int) (string, error) {
	endpoint, err := url.Parse(client.BaseURL)
	if err != nil {
		return "", fmt.Errorf("parse NVD URL: %w", err)
	}
	query := endpoint.Query()
	query.Set("pubStartDate", since.UTC().Format(time.RFC3339))
	query.Set("pubEndDate", until.UTC().Format(time.RFC3339))
	query.Set("resultsPerPage", strconv.Itoa(client.PageSize))
	query.Set("startIndex", strconv.Itoa(startIndex))
	endpoint.RawQuery = query.Encode()
	return endpoint.String(), nil
}

type nvdResponse struct {
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE nvdCVE `json:"cve"`
	} `json:"vulnerabilities"`
}
type nvdCVE struct {
	ID           string                         `json:"id"`
	Published    string                         `json:"published"`
	LastModified string                         `json:"lastModified"`
	Descriptions []struct{ Lang, Value string } `json:"descriptions"`
	Metrics      map[string][]struct {
		CVSSData struct {
			VectorString string  `json:"vectorString"`
			BaseScore    float64 `json:"baseScore"`
			BaseSeverity string  `json:"baseSeverity"`
		} `json:"cvssData"`
		BaseSeverity string `json:"baseSeverity"`
	} `json:"metrics"`
	Configurations []struct {
		Nodes []nvdNode `json:"nodes"`
	} `json:"configurations"`
	References     []struct{ URL, Source string } `json:"references"`
	CISAExploitAdd string                         `json:"cisaExploitAdd"`
}
type nvdNode struct {
	CPEMatch []nvdCPEMatch `json:"cpeMatch"`
	Children []nvdNode     `json:"children"`
}
type nvdCPEMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
}

func ParseNVD(data []byte) ([]model.CVERecord, int, error) {
	var payload nvdResponse
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, 0, fmt.Errorf("decode NVD feed: %w", err)
	}
	records := make([]model.CVERecord, 0, len(payload.Vulnerabilities))
	for _, vulnerability := range payload.Vulnerabilities {
		cve := vulnerability.CVE
		published, err := parseNVDTime(cve.Published)
		if err != nil {
			return nil, 0, fmt.Errorf("%s published date: %w", cve.ID, err)
		}
		modified, err := parseNVDTime(cve.LastModified)
		if err != nil {
			return nil, 0, fmt.Errorf("%s modified date: %w", cve.ID, err)
		}
		record := model.CVERecord{ID: cve.ID, PublishedAt: published, ModifiedAt: modified,
			KnownExploited: cve.CISAExploitAdd != "", SourceURL: "https://nvd.nist.gov/vuln/detail/" + url.PathEscape(cve.ID)}
		for _, description := range cve.Descriptions {
			if description.Lang == "en" {
				record.Description = description.Value
				break
			}
		}
		for _, key := range []string{"cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"} {
			if metrics := cve.Metrics[key]; len(metrics) > 0 {
				record.CVSSScore = metrics[0].CVSSData.BaseScore
				record.CVSSVector = metrics[0].CVSSData.VectorString
				record.Severity = metrics[0].CVSSData.BaseSeverity
				if record.Severity == "" {
					record.Severity = metrics[0].BaseSeverity
				}
				break
			}
		}
		for _, configuration := range cve.Configurations {
			for _, node := range configuration.Nodes {
				appendNodeProducts(&record.Products, node)
			}
		}
		for _, reference := range cve.References {
			record.References = append(record.References, model.CVEReference{URL: reference.URL, Source: reference.Source})
		}
		records = append(records, record)
	}
	return records, payload.TotalResults, nil
}

func appendNodeProducts(products *[]model.AffectedProduct, node nvdNode) {
	for _, match := range node.CPEMatch {
		part, vendor, product, version := parseCPE(match.Criteria)
		*products = append(*products, model.AffectedProduct{CPE23: match.Criteria, Part: part, Vendor: vendor,
			Product: product, Version: version, Vulnerable: match.Vulnerable,
			VersionStartIncluding: match.VersionStartIncluding, VersionStartExcluding: match.VersionStartExcluding,
			VersionEndIncluding: match.VersionEndIncluding, VersionEndExcluding: match.VersionEndExcluding})
	}
	for _, child := range node.Children {
		appendNodeProducts(products, child)
	}
}

func parseCPE(value string) (part, vendor, product, version string) {
	parts := strings.Split(value, ":")
	if len(parts) >= 6 {
		return parts[2], unescapeCPE(parts[3]), unescapeCPE(parts[4]), unescapeCPE(parts[5])
	}
	return "", "", "", ""
}
func unescapeCPE(value string) string { return strings.ReplaceAll(value, `\`, "") }
func parseNVDTime(value string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.000"} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("unsupported timestamp %q", value)
}
