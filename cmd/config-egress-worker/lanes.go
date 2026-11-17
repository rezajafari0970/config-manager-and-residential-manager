package main

// Interleave follow-up slots at every admitted prefix, including when shared
// memory permits admit fewer slots than the CPU governor advertises.
func investigationLane(slot, capacity int, claims uint64) string {
	if capacity == 1 {
		if claims%3 == 2 {
			return "followup"
		}
		return "initial"
	}
	if slot%2 == 0 {
		return "followup"
	}
	return "initial"
}
