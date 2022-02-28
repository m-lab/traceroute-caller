// Package parser handles parsing of scamper output in JSONL format.
package parser

import (
	"errors"
	"fmt"
	"time"
)

var (
	ErrTracerouteType = errors.New("unknown traceroute type")
	ErrTracerouteFile = errors.New("invalid traceroute file")
	ErrMetadata       = errors.New("invalid metadata")
	ErrMetadataUUID   = errors.New("invalid UUID (empty)")
	ErrCycleStart     = errors.New("invalid cycle-start")
	ErrCycleStartType = errors.New("invalid cycle-start type")
	ErrTraceType      = errors.New("invalid traceroute type")
	ErrTraceLine      = errors.New("invalid trace line")
	ErrTracelbLine    = errors.New("invalid tracelb line")
	ErrCycleStop      = errors.New("invalid cycle-stop")
	ErrCycleStopType  = errors.New("invalid cycle-stop type")
)

// TS contains a unix epoch timestamp.
type TS struct {
	Sec  int64 `json:"sec" bigquery:"sec"`
	Usec int64 `json:"usec" bigquery:"usec"`
}

// CyclestartLine contains the information about the scamper "cyclestart".
type CyclestartLine struct {
	Type      string  `json:"type" bigquery:"type"`
	ListName  string  `json:"list_name" bigquery:"list_name"`
	ID        float64 `json:"id" bigquery:"id"`
	Hostname  string  `json:"hostname" bigquery:"hostname"`
	StartTime float64 `json:"start_time" bigquery:"start_time"`
}

// CyclestopLine contains the ending details from the scamper tool.
// ListName, ID, and Hostname seem to match CyclestartLine.
type CyclestopLine struct {
	Type     string  `json:"type" bigquery:"type"`
	ListName string  `json:"list_name" bigquery:"list_name"`
	ID       float64 `json:"id" bigquery:"id"`
	Hostname string  `json:"hostname" bigquery:"hostname"`
	StopTime float64 `json:"stop_time" bigquery:"stop_time"`
}

// ParsedData defines the interface for parsed traceroute data.
type ParsedData interface {
	StartTime() time.Time
	ExtractHops() []string
}

// TracerouteParser defines the interface for raw traceroute data.
type TracerouteParser interface {
	ParseRawData(rawData []byte) (ParsedData, error)
}

// New returns a new traceroute parser correspondong to the traceroute type.
func New(traceType string) (TracerouteParser, error) {
	switch traceType {
	case "mda":
		return &scamper1Parser{}, nil
	case "regular":
		return &scamper2Parser{}, nil
	}
	return nil, fmt.Errorf("%q: %v", traceType, ErrTracerouteType)
}
