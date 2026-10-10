package metrics

import "math"

func uint64FromFloat(f float64) uint64 { return math.Float64bits(f) }

func floatFromUint64(u uint64) float64 { return math.Float64frombits(u) }
