package intelligence

import (
	"strconv"
	"strings"
	"unicode"
)

var productAliases = map[string]struct{ Vendor, Product string }{
	"nginx":              {"nginx", "nginx"},
	"openssh":            {"openbsd", "openssh"},
	"apache":             {"apache", "http_server"},
	"apache http server": {"apache", "http_server"},
	"httpd":              {"apache", "http_server"},
	"redis":              {"redis", "redis"},
	"postgresql":         {"postgresql", "postgresql"},
	"microsoft-iis":      {"microsoft", "internet_information_services"},
}

func NormalizeProduct(observed string) (vendor, product string, ok bool) {
	value := strings.ToLower(strings.TrimSpace(observed))
	value = strings.ReplaceAll(value, "_", " ")
	value = strings.Join(strings.Fields(value), " ")
	mapping, ok := productAliases[value]
	return mapping.Vendor, mapping.Product, ok
}

func VersionAffected(observed string, affectedVersion string, startIncluding, startExcluding, endIncluding, endExcluding string) bool {
	observed = cleanVersion(observed)
	if observed == "" {
		return false
	}
	if affectedVersion != "" && affectedVersion != "*" && affectedVersion != "-" && CompareVersions(observed, affectedVersion) != 0 {
		return false
	}
	if startIncluding != "" && CompareVersions(observed, startIncluding) < 0 {
		return false
	}
	if startExcluding != "" && CompareVersions(observed, startExcluding) <= 0 {
		return false
	}
	if endIncluding != "" && CompareVersions(observed, endIncluding) > 0 {
		return false
	}
	if endExcluding != "" && CompareVersions(observed, endExcluding) >= 0 {
		return false
	}
	return true
}

func CompareVersions(left, right string) int {
	a, b := versionParts(cleanVersion(left)), versionParts(cleanVersion(right))
	limit := len(a)
	if len(b) > limit {
		limit = len(b)
	}
	for i := 0; i < limit; i++ {
		av, bv := versionPart{}, versionPart{}
		if i < len(a) {
			av = a[i]
		}
		if i < len(b) {
			bv = b[i]
		}
		if av.numeric && bv.numeric {
			if av.number < bv.number {
				return -1
			}
			if av.number > bv.number {
				return 1
			}
			continue
		}
		if av.numeric != bv.numeric {
			if av.numeric {
				return 1
			}
			return -1
		}
		if av.text < bv.text {
			return -1
		}
		if av.text > bv.text {
			return 1
		}
	}
	return 0
}

type versionPart struct {
	numeric bool
	number  int64
	text    string
}

func versionParts(value string) []versionPart {
	var parts []versionPart
	for len(value) > 0 {
		digit := unicode.IsDigit(rune(value[0]))
		end := 1
		for end < len(value) && unicode.IsDigit(rune(value[end])) == digit {
			end++
		}
		token := value[:end]
		if digit {
			number, _ := strconv.ParseInt(strings.TrimLeft(token, "0"), 10, 64)
			parts = append(parts, versionPart{numeric: true, number: number})
		} else if token != "." && token != "-" && token != "_" {
			parts = append(parts, versionPart{text: token})
		}
		value = value[end:]
	}
	return parts
}

func cleanVersion(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	return strings.TrimPrefix(value, "v")
}
