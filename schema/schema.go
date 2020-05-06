package schema

import (
	"time"
)

type HopIP struct {
	IP          string `json:"ip,string"`
	City        string `json:"city,string"`
	CountryCode string `json:"country_code,string"`
	Hostname    string `json:"hostname,string"`
	ASN         uint32 `json:"asn,uint32"`
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
	UUID           string       `json:"uuid,string" bigquery:"uuid"`
	TestTime       time.Time    `json:"testtime"`
	StartTime      int64        `json:"start_time,int64" bigquery:"start_time"`
	StopTime       int64        `json:"stop_time,int64" bigquery:"stop_time"`
	ScamperVersion string       `json:"scamper_version,string" bigquery:"scamper_version"`
	ServerIP       string       `json:"serverIP,string" bigquery:"serverip"`
	ClientIP       string       `json:"clientIP,string" bigquery:"clientip"`
	ProbeSize      int64        `json:"probe_size,int64"`
	ProbeC         int64        `json:"probec,int64"`
	Hop            []ScamperHop `json:"hop"`
	ExpVersion     string       `json:"exp_version,string" bigquery:"exp_version"`
	CachedResult   bool         `json:"cached_result,bool" bigquery:"cached_result"`
	CachedUUID     string       `json:"cached_uuid,string" bigquery:"cached_uuid"`
}
