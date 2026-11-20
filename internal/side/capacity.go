package side

// The Side network block has 32 disjoint /30s. Slot zero is reserved for
// the launcher's isolation self-test. The worker and lease service share this limit.
const MaxWorkers = 31
