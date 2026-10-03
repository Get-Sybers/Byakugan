package authoring

// esedump_srum — the Get-Sybers ese_dump SRUM data source (Go-native port of
// byakugan/mappings/esedump_srum.py). Same CAR objects as the Plaso SRUM map,
// its own positional identity. Predicates esedump_srum_is_network_usage /
// _is_application_usage are already in go/internal/predicates.

// the device-path pattern: a raw Go string so the two literal backslashes
// survive (matches r"(?i)^(\\Device\\.+)$" in the Python map / the IR).
const srumDevicePathRe = `(?i)^(\\Device\\.+)$`

// a device path carries the executable; a bare service name is only the exe.
func srumImage() Src { return Regex1("AppIdName", srumDevicePathRe) }
func srumExe() Src   { return First(Basename(srumImage()), "AppIdName") }

// a real SID, never an SRUM-internal numeric index.
func srumSID() Src { return Regex1("UserIdName", `^(S-1-[0-9-]+)$`) }

var srumKeepCommon = []string{
	"Table", "TableAlias", "AppId", "UserId", "AppIdName", "UserIdName", "TimeStamp",
}

func init() {
	register("esedump_srum", Entry{
		Variants: []Variant{
			{Pred: "esedump_srum_is_network_usage", Leaf: &Leaf{
				Object: "flow", Action: "message", Ts: "TimeStamp",
				Guid: GuidFields("AppId", "UserId", "InterfaceLuid", "TimeStamp", "BytesSent", "BytesRecvd"),
				Props: []Prop{
					{"exe", srumExe()},
					{"image_path", srumImage()},
					{"in_bytes", "BytesRecvd"},
					{"out_bytes", "BytesSent"},
					{"uid", srumSID()},
				},
				Keep: append(append([]string{}, srumKeepCommon...),
					"InterfaceLuid", "L2ProfileId", "L2ProfileFlags", "BytesSent", "BytesRecvd"),
			}},
			{Pred: "esedump_srum_is_application_usage", Leaf: &Leaf{
				Object: "process", Action: "create", Ts: "TimeStamp",
				Guid: GuidFields("AppId", "UserId", "TimeStamp"),
				Props: []Prop{
					{"exe", srumExe()},
					{"image_path", srumImage()},
					{"sid", srumSID()},
				},
				Keep: append(append([]string{}, srumKeepCommon...),
					"ForegroundCycleTime", "BackgroundCycleTime", "FaceTime",
					"ForegroundBytesRead", "ForegroundBytesWritten",
					"BackgroundBytesRead", "BackgroundBytesWritten"),
			}},
		},
	})
}
