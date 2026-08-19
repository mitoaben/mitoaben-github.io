package main

import "time"

// timeNowUTC is a small wrapper so tests can stub time if needed.
func timeNowUTC() time.Time { return time.Now().UTC() }
