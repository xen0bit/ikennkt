package nebula

// Anti-replay.
//
// Each tunnel direction carries a 64-bit message counter that also forms the
// AEAD nonce, so a counter must never be accepted twice: replaying a packet
// would otherwise be indistinguishable from the original. UDP reorders freely,
// though, so simply requiring the counter to increase would discard legitimate
// traffic.
//
// The standard answer, and the one nebula uses, is a sliding bitmap: accept
// anything ahead of the highest counter seen, accept anything inside the window
// behind it that has not already arrived, and reject everything older. The
// window is 1024 counters, matching nebula, which is far wider than any
// reordering a real network produces.

// replayWindowSize is the number of counters tracked behind the highest seen.
const replayWindowSize = 1024

// replayWindow tracks which message counters have been accepted.
type replayWindow struct {
	// highest is the largest counter accepted so far.
	highest uint64
	// seen is a bitmap of the window ending at highest, indexed by counter
	// modulo its length.
	seen []bool
}

func newReplayWindow() *replayWindow {
	return &replayWindow{seen: make([]bool, replayWindowSize)}
}

// accept records a counter, reporting false if it is a replay or too old to
// judge. It must be called only after the packet authenticates, so that a
// forged counter cannot advance the window and lock out real traffic.
func (w *replayWindow) accept(counter uint64) bool {
	switch {
	case counter > w.highest:
		// Ahead of everything seen. Clear the slots the window slides past,
		// so a counter that never arrived is not mistaken for one that did
		// when the counter space wraps around the bitmap.
		gap := counter - w.highest
		if gap >= replayWindowSize {
			for i := range w.seen {
				w.seen[i] = false
			}
		} else {
			for i := w.highest + 1; i <= counter; i++ {
				w.seen[i%replayWindowSize] = false
			}
		}
		w.seen[counter%replayWindowSize] = true
		w.highest = counter
		return true

	case w.highest-counter >= replayWindowSize:
		// Older than the window: it cannot be distinguished from a replay.
		return false

	default:
		if w.seen[counter%replayWindowSize] {
			return false
		}
		w.seen[counter%replayWindowSize] = true
		return true
	}
}

// markSeen records counters consumed before the data path starts — the
// handshake messages themselves — so they are not later mistaken for valid
// traffic that went missing.
func (w *replayWindow) markSeen(upTo uint64) {
	for i := uint64(1); i <= upTo; i++ {
		w.accept(i)
	}
}
