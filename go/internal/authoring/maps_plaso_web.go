package authoring

// plaso_web — Plaso browser/download evidence → CAR http (Go-native port of
// byakugan/mappings/plaso_web.py). Endpoint-side records that a URL was
// requested (IE index.dat, Firefox cache, browser history, Java download cache).
// Predicates plasoweb_is_ie_visit / _ff_cache / _ff_visit / _javaidx are already
// in go/internal/predicates. (plr is defined in maps_plasolinux.go.)

// httpProps: the shared derivations for an endpoint-recorded URL request.
func plasoWebHTTPProps(urlMarker Src) []Prop {
	return []Prop{
		{"url_full", urlMarker},
		{"url_scheme", Regex1(urlMarker, `^(https?)://`)},
		{"url_domain", Regex1(urlMarker, `^https?://([^/?#:]+)`)},
		{"url_remainder", Regex1(urlMarker, `^https?://[^/]+(/[^\s]*)`)},
		{"hostname", plr("image_hostname")},
	}
}

// IE history renders "Visited: user@<url>"; plain cache rows carry the bare url.
func ieURL() Src { return First(Regex1(plr("url"), `^Visited:\s*[^@]*@(.+)$`), plr("url")) }

// firefox cache prefixes the url with "HTTP:".
func ffcURL() Src { return First(Regex1(plr("url"), `^HTTP:(.+)$`), plr("url")) }

func plasoWebHost() Src { return HostLabel(plr("image_hostname")) }

func init() {
	register("l2t_msiecf", Entry{
		Variants: []Variant{
			{Pred: "plasoweb_is_ie_visit", Leaf: &Leaf{
				Object: "http", Action: "get", Ts: "Timestamp",
				Guid: GuidSpindle("l2t_msiecf"), Host: plasoWebHost(),
				Props: plasoWebHTTPProps(ieURL()),
				NativeExtract: []Prop{
					{"data_type", plr("data_type")},
					{"raw_url", plr("url")},
					{"number_of_hits", plr("number_of_hits")},
					{"artefact_file", plr("display_name")},
				},
			}},
		},
	})
	register("l2t_firefox_cache", Entry{
		Variants: []Variant{
			{Pred: "plasoweb_is_ff_cache", Leaf: &Leaf{
				Object: "http",
				Action: MapValue(plr("request_method"),
					map[string]string{"GET": "get", "POST": "post", "PUT": "put"}, true),
				Ts:   "Timestamp",
				Guid: GuidSpindle("l2t_firefox_cache"), Host: plasoWebHost(),
				Props: append(plasoWebHTTPProps(ffcURL()),
					Prop{"response_status_code", HexInt(Regex1(plr("response_code"), `\s(\d{3})\s`))}),
				NativeExtract: []Prop{
					{"data_type", plr("data_type")},
					{"fetch_count", plr("fetch_count")},
					{"data_size", plr("data_size")},
					{"artefact_file", plr("display_name")},
				},
			}},
		},
	})
	register("l2t_firefox_places", Entry{
		Variants: []Variant{
			{Pred: "plasoweb_is_ff_visit", Leaf: &Leaf{
				Object: "http", Action: "get", Ts: "Timestamp",
				Guid: GuidSpindle("l2t_firefox_places"), Host: plasoWebHost(),
				Props: append(plasoWebHTTPProps(plr("url")),
					Prop{"request_referrer", First(Regex1(plr("from_visit"), `^(\S+)`), plr("from_visit"))},
					Prop{"response_body_bytes", plr("received_bytes")}),
				NativeExtract: []Prop{
					{"data_type", plr("data_type")},
					{"title", plr("title")},
					{"visit_count", plr("visit_count")},
					{"visit_type", plr("visit_type")},
					{"typed", plr("typed")},
					{"total_bytes", plr("total_bytes")},
					{"full_path", plr("full_path")},
					{"artefact_file", plr("display_name")},
				},
			}},
		},
	})
	register("l2t_javaidx", Entry{
		Variants: []Variant{
			{Pred: "plasoweb_is_javaidx", Leaf: &Leaf{
				Object: "http", Action: "get", Ts: "Timestamp",
				Guid: GuidSpindle("l2t_javaidx"), Host: plasoWebHost(),
				Props: plasoWebHTTPProps(plr("url")),
				NativeExtract: []Prop{
					{"data_type", plr("data_type")},
					{"ip_address", plr("ip_address")},
					{"idx_version", plr("idx_version")},
					{"artefact_file", plr("display_name")},
				},
			}},
		},
	})
}
