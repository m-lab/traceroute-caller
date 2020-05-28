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
	Flowid int64     `json:"flowid,int64"`
	Rtt    []float64 `json:"rtt"`
}

type HopLink struct {
	HopDstIP string     `json:"hop_dst_ip,string"`
	TTL      int64      `json:"ttl,int64"`
	Probes   []HopProbe `json:"probes"`
}

type ScamperHop struct {
	Source HopIP     `json:"source"`
	Linkc  int64     `json:"linkc,int64"`
	Links  []HopLink `json:"link"`
}

type PTTestRaw struct {
	SchemaVersion          string       `json:"schema_version" bigquery:"schema_version"`
	UUID                   string       `json:"uuid" bigquery:"uuid"`
	TestTime               time.Time    `json:"testtime"`
	StartTime              int64        `json:"start_time,int64" bigquery:"start_time"`
	StopTime               int64        `json:"stop_time,int64" bigquery:"stop_time"`
	ScamperVersion         string       `json:"scamper_version" bigquery:"scamper_version"`
	ServerIP               string       `json:"serverIP" bigquery:"serverip"`
	ClientIP               string       `json:"clientIP" bigquery:"clientip"`
	ProbeSize              int64        `json:"probe_size,int64"`
	ProbeC                 int64        `json:"probec,int64"`
	Hop                    []ScamperHop `json:"hop"`
	CachedResult           bool         `json:"cached_result,bool" bigquery:"cached_result"`
	CachedUUID             string       `json:"cached_uuid" bigquery:"cached_uuid"`
	TracerouteCallerCommit string       `json:"traceroutecaller_commit" bigquery:"traceroutecaller_caller"`
}
