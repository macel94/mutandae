package protocol

import (
	"fmt"
	"strings"
	"time"
)

// ISO-8601 duration helpers. Go's time.Duration does not serialize portably to
// JSON, so the protocol represents renewal/grace/max-age periods as ISO-8601
// duration strings (e.g. "P90D", "P14D", "PT6h"). These helpers convert to and
// from time.Duration for control-plane math. Fractional seconds beyond
// millisecond precision are not supported.

// ParseISO8601Duration parses a supported ISO-8601 duration. Supported forms:
//
//	P{n}D, P{n}W, PT{n}H, PT{n}M, PT{n}S and combinations such as P1DT6H.
//
// Decimal seconds are supported to millisecond precision.
func ParseISO8601Duration(value string) (time.Duration, error) {
	s := strings.TrimSpace(value)
	if !strings.HasPrefix(s, "P") || len(s) < 2 {
		return 0, fmt.Errorf("protocol: invalid ISO-8601 duration %q", value)
	}
	s = s[1:]

	token := ""
	inTime := false
	total := time.Duration(0)
	count := 0
	flush := func(unit byte) error {
		if token == "" {
			return fmt.Errorf("protocol: empty value before unit %q in %q", unit, value)
		}
		var amount float64
		if _, err := fmt.Sscanf(token, "%f", &amount); err != nil {
			return fmt.Errorf("protocol: invalid number %q in %q", token, value)
		}
		d, err := isoUnit(unit, amount)
		if err != nil {
			return err
		}
		total += d
		count++
		token = ""
		return nil
	}

	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == 'T':
			if token != "" {
				return 0, fmt.Errorf("protocol: misplaced time designator in %q", value)
			}
			inTime = true
		case c >= '0' && c <= '9' || c == '.':
			token += string(c)
		case c == 'Y' || c == 'M' || c == 'D' || c == 'W' || c == 'H' || c == 'S':
			if !inTime && (c == 'H' || c == 'S') {
				return 0, fmt.Errorf("protocol: %q must follow the time designator in %q", string(c), value)
			}
			if !inTime && c == 'M' {
				// M before T is month (unsupported) — reject rather than guess.
				return 0, fmt.Errorf("protocol: months are not supported in %q", value)
			}
			if err := flush(c); err != nil {
				return 0, err
			}
		default:
			return 0, fmt.Errorf("protocol: unexpected character %q in %q", string(c), value)
		}
	}
	if token != "" {
		return 0, fmt.Errorf("protocol: trailing value %q in %q", token, value)
	}
	if count == 0 {
		return 0, fmt.Errorf("protocol: no duration components in %q", value)
	}
	return total, nil
}

func isoUnit(unit byte, amount float64) (time.Duration, error) {
	switch unit {
	case 'D':
		return time.Duration(amount * float64(24*time.Hour)), nil
	case 'W':
		return time.Duration(amount * float64(7*24*time.Hour)), nil
	case 'H':
		return time.Duration(amount * float64(time.Hour)), nil
	case 'M':
		return time.Duration(amount * float64(time.Minute)), nil
	case 'S':
		return time.Duration(amount * float64(time.Second)), nil
	default:
		return 0, fmt.Errorf("protocol: unsupported unit %q", unit)
	}
}

// FormatISO8601Duration renders a duration as a compact ISO-8601 duration
// string, omitting zero-value components. Whole days become "P{n}D"; sub-day
// components appear after a time designator (e.g. 6h -> "P0DT6H"). The output
// is always parseable by ParseISO8601Duration.
func FormatISO8601Duration(d time.Duration) string {
	if d <= 0 {
		return "P0D"
	}
	var b strings.Builder
	b.WriteString("P")
	days := d / (24 * time.Hour)
	d %= 24 * time.Hour
	if days > 0 {
		fmt.Fprintf(&b, "%dD", days)
	}
	wroteTime := false
	hours := d / time.Hour
	d %= time.Hour
	minutes := d / time.Minute
	d %= time.Minute
	seconds := d / time.Second
	ms := d % time.Second / time.Millisecond

	if hours > 0 || minutes > 0 || seconds > 0 || ms > 0 {
		b.WriteString("T")
		wroteTime = true
	}
	if hours > 0 {
		fmt.Fprintf(&b, "%dH", hours)
	}
	if minutes > 0 {
		fmt.Fprintf(&b, "%dM", minutes)
	}
	if seconds > 0 || ms > 0 {
		if ms > 0 {
			fmt.Fprintf(&b, "%d.%03dS", seconds, ms)
		} else {
			fmt.Fprintf(&b, "%dS", seconds)
		}
	}
	_ = wroteTime // retained for clarity; sub-second branch above emits the T.
	return b.String()
}
