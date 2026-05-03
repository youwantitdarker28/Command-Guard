// Package ui implements the Bubble Tea TUI presented to the user before a
// command is executed. It renders a Lip Gloss styled card with the full risk
// assessment and waits for an Approve or Abort decision.
package ui

import (
	"strings"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/digest/internal/analyzer"
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
	result   analyzer.Result
	selected choice
	approved bool
}

func newModel(r analyzer.Result) model {
	return model{result: r, selected: choiceApprove}
}

func (m model) Init() tea.Cmd { return nil }

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	km, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	switch {
	case key.Matches(km, keys.Quit):
		m.approved = false
		return m, tea.Quit
	case key.Matches(km, keys.Left):
		m.selected = choiceApprove
	case key.Matches(km, keys.Right):
		m.selected = choiceAbort
	case key.Matches(km, keys.Tab):
		if m.selected == choiceApprove {
			m.selected = choiceAbort
		} else {
			m.selected = choiceApprove
		}
	case key.Matches(km, keys.Enter):
		m.approved = m.selected == choiceApprove
		return m, tea.Quit
	}
	return m, nil
}

// ── Palette ───────────────────────────────────────────────────────────────────

var (
	clrHigh    = lipgloss.Color("#FF3B3B")
	clrMedium  = lipgloss.Color("#FFB347")
	clrLow     = lipgloss.Color("#3BE08B")
	clrApprove = lipgloss.Color("#22CC66")
	clrAbort   = lipgloss.Color("#FF3B55")
	clrMuted   = lipgloss.Color("#6E6E8E")
	clrSubtle  = lipgloss.Color("#AAAAC0")
	clrAccent  = lipgloss.Color("#7C6AFF")
	clrPkg     = lipgloss.Color("#5DD8FF")
	clrCaution = lipgloss.Color("#FFB347")
	clrBg      = lipgloss.Color("#0F0F1A")
	clrBorder  = lipgloss.Color("#252538")
	clrTitle   = lipgloss.Color("#EEEEFF")

	// Card — the outermost container.
	cardStyle = lipgloss.NewStyle().
			Background(clrBg).
			Border(lipgloss.ThickBorder()).
			BorderForeground(clrBorder).
			Padding(1, 3).
			Width(66)

	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(clrTitle)

	labelStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(clrMuted).
			MarginTop(1)

	cmdStyle = lipgloss.NewStyle().
			Foreground(clrAccent).
			Bold(true).
			Background(lipgloss.Color("#1A1A2E")).
			Padding(0, 1)

	subtleStyle = lipgloss.NewStyle().Foreground(clrSubtle)
	italicStyle = lipgloss.NewStyle().Foreground(clrSubtle).Italic(true)
	divStyle    = lipgloss.NewStyle().Foreground(clrBorder)
	hintStyle   = lipgloss.NewStyle().Foreground(clrMuted).Italic(true)
	pkgStyle    = lipgloss.NewStyle().Foreground(clrPkg).Bold(true)
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

func div() string { return divStyle.Render(strings.Repeat("─", 60)) }

// ── View ──────────────────────────────────────────────────────────────────────

func (m model) View() string {
	r := m.result

	// Header row: title + threat badge
	header := lipgloss.JoinHorizontal(
		lipgloss.Left,
		titleStyle.Render("digest"),
		"   ",
		riskBadge(r.Risk),
	)

	// Command section
	cmdSection := lipgloss.JoinVertical(lipgloss.Left,
		labelStyle.Render("COMMAND"),
		cmdStyle.Render("$ "+r.Command),
	)

	// Package section (only for package manager installs)
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

	// Threat level section
	tc := threatColor(r.Risk)
	threatSection := lipgloss.JoinVertical(lipgloss.Left,
		labelStyle.Render("THREAT LEVEL"),
		lipgloss.NewStyle().Foreground(tc).Bold(true).Render("▲  ")+subtleStyle.Render(r.ThreatSummary),
	)

	// Prompt tip section
	tipSection := lipgloss.JoinVertical(lipgloss.Left,
		labelStyle.Render("PROMPT TIP"),
		lipgloss.NewStyle().Foreground(clrAccent).Render("ℹ  ")+italicStyle.Render(r.PromptTip),
	)

	// Action buttons
	actionSection := lipgloss.JoinVertical(lipgloss.Left,
		labelStyle.Render("ACTION"),
		lipgloss.JoinHorizontal(lipgloss.Left,
			btn("✓  Approve", m.selected == choiceApprove, clrApprove),
			"    ",
			btn("✗  Abort", m.selected == choiceAbort, clrAbort),
		),
	)

	// Key hint
	hint := hintStyle.Render("← → tab  navigate    enter  confirm    q / esc  quit")

	// Assemble — conditionally insert package section
	sections := []string{header, div(), cmdSection}
	if r.IsPackageInstall {
		sections = append(sections, div(), pkgSection)
	}
	sections = append(sections, div(), threatSection, tipSection, div(), actionSection, "", hint)

	return "\n" + cardStyle.Render(lipgloss.JoinVertical(lipgloss.Left, sections...)) + "\n"
}

// ── Public API ────────────────────────────────────────────────────────────────

// Run launches the interactive TUI and blocks until the user makes a decision.
// It writes all TUI output to stderr so that stdout remains clean for command
// output after approval.
// Returns true if the user approved, false if they aborted or quit.
func Run(r analyzer.Result) (bool, error) {
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
