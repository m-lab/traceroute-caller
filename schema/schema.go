package schema

import (
	"time"

	"github.com/m-lab/uuid-annotator/annotator"
)

type HopIP struct {
	IP       string                 `json:"ip"`
	Hostname string                 `json:"hostname"`
	Geo      *annotator.Geolocation `json:"geo"`
	Network  *annotator.Network     `json:"network"`
}

type HopProbe struct {
	Flowid int64     `json:"flowid"`
	Rtt    []float64 `json:"rtt"`
}

type HopLink struct {
	HopDstIP string     `json:"hop_dst_ip"`
	TTL      int64      `json:"ttl"`
	Probes   []HopProbe `json:"probes"`
}

type ScamperHop struct {
	Source HopIP     `json:"source"`
	Linkc  int64     `json:"linkc"`
	Links  []HopLink `json:"link"`
}

type PTTestRaw struct {
	SchemaVersion          string       `json:"schema_version" bigquery:"schema_version"`
	UUID                   string       `json:"uuid" bigquery:"uuid"`
	TestTime               time.Time    `json:"testtime"`
	StartTime              int64        `json:"start_time" bigquery:"start_time"`
	StopTime               int64        `json:"stop_time" bigquery:"stop_time"`
	ScamperVersion         string       `json:"scamper_version" bigquery:"scamper_version"`
	ServerIP               string       `json:"serverIP" bigquery:"serverip"`
	ClientIP               string       `json:"clientIP" bigquery:"clientip"`
	ProbeSize              int64        `json:"probe_size"`
	ProbeC                 int64        `json:"probec"`
	Hop                    []ScamperHop `json:"hop"`
	CachedResult           bool         `json:"cached_result" bigquery:"cached_result"`
	CachedUUID             string       `json:"cached_uuid" bigquery:"cached_uuid"`
	TracerouteCallerCommit string       `json:"traceroutecaller_commit" bigquery:"traceroutecaller_caller"`
}
