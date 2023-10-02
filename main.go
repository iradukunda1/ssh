package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/charmbracelet/bubbles/textarea"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/promwish"
	"github.com/charmbracelet/ssh"
	"github.com/charmbracelet/wish"
	bm "github.com/charmbracelet/wish/bubbletea"
	lm "github.com/charmbracelet/wish/logging"
	"github.com/muesli/termenv"
)

const (
	host     = "127.0.0.1"
	port     = 23234
	promPort = "23235"
)

type app struct {
	*ssh.Server
	progs []*tea.Program
}

type model struct {
	*app
	viewport    viewport.Model
	messages    []string
	id          string
	textarea    textarea.Model
	senderStyle lipgloss.Style
	err         error
}

type (
	errMsg  error
	chatMsg struct {
		id   string
		text string
	}
)

func main1() {
	app := new(app)

	s, err := wish.NewServer(
		wish.WithAddress(fmt.Sprintf("%s:%d", host, port)),
		wish.WithMiddleware(
			bm.MiddlewareWithProgramHandler(app.ProgramHandler, termenv.ANSI256),
			promwish.Middleware(fmt.Sprintf("%s:%s", host, promPort), "lists-ssh"),
			lm.Middleware(),
		),
	)

	if err != nil {
		log.Fatalln(err)
	}

	app.Server = s

	app.Start()
}

func (a *app) send(msg tea.Msg) {
	for _, p := range a.progs {
		go p.Send(msg)
	}
}

func (a *app) Start() {
	var err error
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	log.Printf("Starting SSH server on %s:%d", host, port)
	go func() {
		if err = a.ListenAndServe(); err != nil {
			log.Fatalln(err)
		}
	}()

	<-done
	log.Println("Stopping SSH server")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer func() { cancel() }()
	if err := a.Shutdown(ctx); err != nil {
		log.Fatalln(err)
	}
}

func (a *app) ProgramHandler(s ssh.Session) *tea.Program {
	pty, _, active := s.Pty()
	if !active {
		wish.Fatalln(s, "terminal is not active")
	}

	m := a.initialModel(s.User())

	m.viewport.Width = pty.Window.Width
	m.textarea.SetWidth(pty.Window.Width)

	p := tea.NewProgram(m, tea.WithOutput(s), tea.WithInput(s))
	a.progs = append(a.progs, p)

	return p
}

func (a *app) initialModel(user string) model {
	ta := textarea.New()
	ta.Placeholder = ""
	ta.Focus()

	ta.Prompt = "#"
	ta.CharLimit = 0

	ta.SetWidth(35)
	ta.SetHeight(2)

	// Remove cursor line styling
	ta.FocusedStyle.CursorLine = lipgloss.NewStyle()

	ta.ShowLineNumbers = false

	vp := viewport.New(30, 3)
	// 	vp.SetContent(`Welcome to the drop ssh shell!
	// Type a message and press Enter to send.`)
	vp.MouseWheelEnabled = true

	ta.KeyMap.InsertNewline.SetEnabled(true)

	return model{
		id:          user,
		app:         a,
		textarea:    ta,
		messages:    []string{},
		viewport:    vp,
		senderStyle: lipgloss.NewStyle().Foreground(lipgloss.Color("5")),
		err:         nil,
	}
}

func (m model) Init() tea.Cmd {
	return textarea.Blink
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var (
		tiCmd tea.Cmd
		vpCmd tea.Cmd
	)

	m.textarea, tiCmd = m.textarea.Update(msg)
	m.viewport, vpCmd = m.viewport.Update(msg)

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyCtrlC, tea.KeyEsc, tea.KeyCtrlQ:
			return m, tea.Quit
		case tea.KeyEnter:
			m.app.send(chatMsg{
				id:   m.id,
				text: m.textarea.Value(),
			})
			m.textarea.SetCursor(-1)
			m.textarea.Reset()
		}

	case chatMsg:
		cmd, _ := executeCommand(msg.text)
		m.messages = append(m.messages, m.senderStyle.Render(msg.id)+"@dedsec# "+msg.text+cmd)
		m.viewport.SetContent(strings.Join(m.messages, "\n"))
		m.viewport.KeyMap.PageDown.SetEnabled(true)
		m.viewport.KeyMap.PageUp.SetEnabled(true)
		m.viewport.GotoBottom()

	case errMsg:
		m.err = msg
		return m, nil
	}

	return m, tea.Batch(tiCmd, vpCmd)
}

func (m model) View() string {
	out, _ := executeCommand("cat /etc/hostname")
	s := fmt.Sprintf("Host:%s", out)
	s += "Welcome to the drop ssh shell!\n"
	s += fmt.Sprintf("Time:%s\n", time.Now().Format(time.RFC1123))

	s += "Press 'cmd' to execute a command\n"
	s += "Press 'esc' or ctl + c to quit"

	return fmt.Sprintf("%s\n%s\n%s", s, m.viewport.View(), m.textarea.View())
}

// Function to execute shell commands and capture output
func executeCommand(cmd string) (string, error) {
	output, err := exec.Command("/bin/sh", []string{`-c`, cmd}...).CombinedOutput()
	if err != nil {
		return "", err
	}
	return string(output), nil
}
