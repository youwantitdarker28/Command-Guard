// Package ui implements the Bubble Tea TUI presented to the user before a
// command is executed. It renders a Lip Gloss styled card with the full risk
// assessment and waits for an Approve or Abort decision.
//
// Setting the environment variable DIGEST_AUTO_APPROVE=1 bypasses the
// interactive prompt and immediately returns approved=true. This is intended
// for use in CI pipelines and smoke tests only.
package ui

import (
	"os"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/digest/internal/analyzer"
)

// ── Layout constants ──────────────────────────────────────────────────────────

const (
	// cardOverhead is the total horizontal space consumed by the card's border
	// (ThickBorder = 1 char each side = 2) and horizontal padding (3 each side = 6).
	cardOverhead = 8

	// cardMargin is the gap left on each side of the card so it does not touch
	// the terminal edge.
	cardMargin = 4

	defaultWidth = 66 // content width used before the first WindowSizeMsg
	minWidth     = 36 // never go narrower than this (mobile / small panes)
	maxWidth     = 80 // cap to keep lines readable on wide terminals
)

// ── Key bindings ──────────────────────────────────────────────────────────────

type keyMap struct {
	Left  key.Binding
	Right key.Binding
	Tab   key.Binding
	Enter key.Binding
	Quit  key.Binding
}

var keys = keyMap{
	Left:  key.NewBinding(key.WithKeys("left", "h")),
	Right: key.NewBinding(key.WithKeys("right", "l")),
	Tab:   key.NewBinding(key.WithKeys("tab")),
	Enter: key.NewBinding(key.WithKeys("enter")),
	Quit:  key.NewBinding(key.WithKeys("ctrl+c", "q", "esc")),
}

// ── Model ─────────────────────────────────────────────────────────────────────

type choice int

const (
	choiceApprove choice = iota
	choiceAbort
)

type model struct {
	result     analyzer.Result
	selected   choice
	approved   bool
	// width is the Lip Gloss *content* width of the card (excludes border/padding).
	// It is updated on every tea.WindowSizeMsg.
	width      int
}

func newModel(r analyzer.Result) model {
	return model{result: r, selected: choiceApprove, width: defaultWidth}
}

// clamp returns v clamped to [lo, hi].
func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func (m model) Init() tea.Cmd { return nil }

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	// ── Terminal resize / initial size ────────────────────────────────────────
	case tea.WindowSizeMsg:
		// Derive content width from terminal width, accounting for card chrome.
		m.width = clamp(msg.Width-cardOverhead-cardMargin, minWidth, maxWidth)
		return m, nil

	// ── Keyboard ──────────────────────────────────────────────────────────────
	case tea.KeyMsg:
		switch {
		case key.Matches(msg, keys.Quit):
			m.approved = false
			return m, tea.Quit
		case key.Matches(msg, keys.Left):
			m.selected = choiceApprove
		case key.Matches(msg, keys.Right):
			m.selected = choiceAbort
		case key.Matches(msg, keys.Tab):
			if m.selected == choiceApprove {
				m.selected = choiceAbort
			} else {
				m.selected = choiceApprove
			}
		case key.Matches(msg, keys.Enter):
			m.approved = m.selected == choiceApprove
			return m, tea.Quit
		}
	}
	return m, nil
}

// ── Palette ───────────────────────────────────────────────────────────────────

var (
	clrHigh     = lipgloss.Color("#FF3B3B")
	clrMedium   = lipgloss.Color("#FFB347")
	clrLow      = lipgloss.Color("#3BE08B")
	clrApprove  = lipgloss.Color("#22CC66")
	clrAbort    = lipgloss.Color("#FF3B55")
	clrMuted    = lipgloss.Color("#6E6E8E")
	clrSubtle   = lipgloss.Color("#AAAAC0")
	clrAccent   = lipgloss.Color("#7C6AFF")
	clrPkg      = lipgloss.Color("#5DD8FF")
	clrCaution  = lipgloss.Color("#FFB347")
	clrBg       = lipgloss.Color("#0F0F1A")
	clrBorder   = lipgloss.Color("#252538")
	clrTitle    = lipgloss.Color("#EEEEFF")

	titleStyle   = lipgloss.NewStyle().Bold(true).Foreground(clrTitle)
	labelStyle   = lipgloss.NewStyle().Bold(true).Foreground(clrMuted).MarginTop(1)
	cmdStyle     = lipgloss.NewStyle().Foreground(clrAccent).Bold(true).Background(lipgloss.Color("#1A1A2E")).Padding(0, 1)
	subtleStyle  = lipgloss.NewStyle().Foreground(clrSubtle)
	italicStyle  = lipgloss.NewStyle().Foreground(clrSubtle).Italic(true)
	divStyle     = lipgloss.NewStyle().Foreground(clrBorder)
	hintStyle    = lipgloss.NewStyle().Foreground(clrMuted).Italic(true)
	pkgStyle     = lipgloss.NewStyle().Foreground(clrPkg).Bold(true)
	cautionStyle = lipgloss.NewStyle().Foreground(clrCaution).Bold(true)
)

// ── Helper renderers ──────────────────────────────────────────────────────────

func riskBadge(r analyzer.RiskLevel) string {
	var bg lipgloss.Color
	var label string
	switch r {
	case analyzer.RiskHigh:
		bg, label = clrHigh, "  ● HIGH  "
	case analyzer.RiskMedium:
		bg, label = clrMedium, "  ◐ MEDIUM  "
	case analyzer.RiskLow:
		bg, label = clrLow, "  ○ LOW  "
	}
	return lipgloss.NewStyle().
		Background(bg).
		Foreground(lipgloss.Color("#000000")).
		Bold(true).
		Padding(0, 1).
		Render(label)
}

func threatColor(r analyzer.RiskLevel) lipgloss.Color {
	switch r {
	case analyzer.RiskHigh:
		return clrHigh
	case analyzer.RiskMedium:
		return clrMedium
	default:
		return clrLow
	}
}

func btn(label string, active bool, activeColor lipgloss.Color) string {
	s := lipgloss.NewStyle().Padding(0, 4).Bold(true)
	if active {
		return s.Background(activeColor).Foreground(lipgloss.Color("#000000")).Render(label)
	}
	return s.Foreground(activeColor).
		Border(lipgloss.NormalBorder()).
		BorderForeground(activeColor).
		Render(label)
}

// ── View ──────────────────────────────────────────────────────────────────────

func (m model) View() string {
	r := m.result
	w := m.width

	// Card style — width is dynamic, computed from window size.
	card := lipgloss.NewStyle().
		Background(clrBg).
		Border(lipgloss.ThickBorder()).
		BorderForeground(clrBorder).
		Padding(1, 3).
		Width(w)

	// Horizontal rule scaled to content width.
	hr := divStyle.Render(strings.Repeat("─", w))

	// Centered placement: wrap the card in a container that fills the terminal
	// width and uses lipgloss.Center alignment.
	center := lipgloss.NewStyle().Width(w + cardOverhead).Align(lipgloss.Center)
	_ = center // used below in the return

	// Header row: title + risk badge.
	header := lipgloss.JoinHorizontal(lipgloss.Left,
		titleStyle.Render("digest"),
		"   ",
		riskBadge(r.Risk),
	)

	// Command section.
	cmdSection := lipgloss.JoinVertical(lipgloss.Left,
		labelStyle.Render("COMMAND"),
		cmdStyle.Render("$ "+r.Command),
	)

	// Package section (only for package-manager installs).
	var pkgSection string
	if r.IsPackageInstall {
		rows := []string{labelStyle.Render("PACKAGES  (" + r.PackageManager + ")")}
		if len(r.Packages) == 0 {
			rows = append(rows,
				italicStyle.Render("  (installing from lockfile or manifest — no explicit package listed)"),
			)
		} else {
			for _, p := range r.Packages {
				rows = append(rows, "  "+pkgStyle.Render("▸ "+p))
			}
		}
		rows = append(rows, "",
			cautionStyle.Render("⚡ Caution: ")+
				subtleStyle.Render("This will execute external code during the installation process."),
		)
		pkgSection = lipgloss.JoinVertical(lipgloss.Left, rows...)
	}

	// Threat level section.
	tc := threatColor(r.Risk)
	threatSection := lipgloss.JoinVertical(lipgloss.Left,
		labelStyle.Render("THREAT LEVEL"),
		lipgloss.NewStyle().Foreground(tc).Bold(true).Render("▲  ")+subtleStyle.Render(r.ThreatSummary),
	)

	// Prompt tip section.
	tipSection := lipgloss.JoinVertical(lipgloss.Left,
		labelStyle.Render("PROMPT TIP"),
		lipgloss.NewStyle().Foreground(clrAccent).Render("ℹ  ")+italicStyle.Render(r.PromptTip),
	)

	// Action buttons.
	actionSection := lipgloss.JoinVertical(lipgloss.Left,
		labelStyle.Render("ACTION"),
		lipgloss.JoinHorizontal(lipgloss.Left,
			btn("✓  Approve", m.selected == choiceApprove, clrApprove),
			"    ",
			btn("✗  Abort", m.selected == choiceAbort, clrAbort),
		),
	)

	hint := hintStyle.Render("← → tab  navigate    enter  confirm    q / esc  quit")

	sections := []string{header, hr, cmdSection}
	if r.IsPackageInstall {
		sections = append(sections, hr, pkgSection)
	}
	sections = append(sections, hr, threatSection, tipSection, hr, actionSection, "", hint)

	return "\n" + center.Render(card.Render(lipgloss.JoinVertical(lipgloss.Left, sections...))) + "\n"
}

// ── Public API ────────────────────────────────────────────────────────────────

// Run launches the interactive TUI and blocks until the user makes a decision.
// All TUI output is written to stderr so that stdout remains clean for the
// executed command's output after approval.
//
// Returns (true, nil) on approval, (false, nil) on abort/quit, or (false, err)
// if the TUI itself encounters a fatal error.
//
// If the environment variable DIGEST_AUTO_APPROVE=1 is set, Run skips the TUI
// entirely and returns (true, nil). This is intended for CI and smoke tests.
func Run(r analyzer.Result) (bool, error) {
	if os.Getenv("DIGEST_AUTO_APPROVE") == "1" {
		return true, nil
	}

	m := newModel(r)
	p := tea.NewProgram(m, tea.WithOutput(stderr()))
	final, err := p.Run()
	if err != nil {
		return false, err
	}
	fm, ok := final.(model)
	if !ok {
		return false, nil
	}
	return fm.approved, nil
}
