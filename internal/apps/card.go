package apps

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Dashboard cards ("You should know", YSK) on the ZimaOS home screen, sent
// through the ZimaOS message bus. Measured on 1.8.0-beta2 (KB §75):
//   - a card is delivered live to the dashboards open at that moment and is
//     NOT stored — a reload drops it, GET /ysk stays empty. A pending question
//     is therefore re-sent periodically (Notifier.Refresh) until answered;
//   - a footer button can only open a URL: the dashboard handles the key
//     "casaos-ui:open_files" (window.open(origin + "/" + payload.url)) and
//     nothing that would carry the answer itself, so the card says what
//     happened and opens ZFW for the decision.

// DefaultBusURLFile is where ZimaOS records the message bus address.
const DefaultBusURLFile = "/var/run/casaos/message-bus.url"

// Notifier posts and withdraws cards. The zero BusURLFile disables it.
type Notifier struct {
	BusURLFile string
	Client     *http.Client
}

type yskCard struct {
	ID         string     `json:"id"`
	CardType   string     `json:"cardType"`
	RenderType string     `json:"renderType"`
	Content    yskContent `json:"content"`
}

type yskContent struct {
	TitleIcon        string         `json:"titleIcon"`
	TitleText        string         `json:"titleText"`
	BodyIconWithText *yskIconText   `json:"bodyIconWithText,omitempty"`
	FooterActions    []yskFooterAct `json:"footerActions,omitempty"`
}

type yskIconText struct {
	Icon        string `json:"icon"`
	Description string `json:"description"`
}

type yskFooterAct struct {
	Side       string    `json:"side"`
	Style      string    `json:"style"`
	Text       string    `json:"text"`
	MessageBus yskBusAct `json:"messageBus"`
}

type yskBusAct struct {
	Key     string `json:"key"`
	Payload string `json:"payload"`
}

const cardIcon = "/modules/zfw/appicon.svg"

// CardID is stable per entry, so a re-send replaces the card instead of
// stacking a second one.
func CardID(e Entry) string { return "zfw:app:" + e.Key }

// CardText is the card's body, in English like the whole ZFW UI.
func CardText(e Entry, mode string) string {
	what := fmt.Sprintf("%s opened port %d/%s.", e.Title, e.Port, e.Proto)
	if mode == ModeBlock {
		return what + " ZFW keeps it closed until you decide who may reach it."
	}
	return what + " ZFW made it reachable from your LAN only — decide whether that stays, opens to everyone, or closes."
}

func buildCard(e Entry, mode string) yskCard {
	open, _ := json.Marshal(map[string]string{"url": "modules/zfw/index.html#apps"})
	return yskCard{
		ID: CardID(e), CardType: "long-notice", RenderType: "icon-text-notice",
		Content: yskContent{
			TitleIcon: cardIcon,
			TitleText: "ZFW Firewall — new app port",
			BodyIconWithText: &yskIconText{
				Icon: cardIcon, Description: CardText(e, mode),
			},
			FooterActions: []yskFooterAct{{
				Side: "right", Style: "primary", Text: "Decide in ZFW",
				MessageBus: yskBusAct{Key: "casaos-ui:open_files", Payload: string(open)},
			}},
		},
	}
}

func (n Notifier) busURL() (string, error) {
	b, err := os.ReadFile(n.BusURLFile)
	if err != nil {
		return "", err
	}
	u, err := url.Parse(strings.TrimSpace(string(b)))
	if err != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" {
		// The bus is a local service; never follow the file anywhere else.
		return "", fmt.Errorf("message bus url %q is not a loopback http url", strings.TrimSpace(string(b)))
	}
	return strings.TrimRight(u.String(), "/"), nil
}

func (n Notifier) publish(ctx context.Context, event string, props map[string]string) error {
	if n.BusURLFile == "" {
		return nil
	}
	base, err := n.busURL()
	if err != nil {
		return err
	}
	body, _ := json.Marshal(props)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		base+"/v2/message_bus/event/ysk/"+url.PathEscape(event), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	c := n.Client
	if c == nil {
		c = http.DefaultClient
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("message bus %s: HTTP %d", event, resp.StatusCode)
	}
	return nil
}

// Show sends (or re-sends) the card for a pending entry.
func (n Notifier) Show(ctx context.Context, e Entry, mode string) error {
	card, err := json.Marshal(buildCard(e, mode))
	if err != nil {
		return err
	}
	return n.publish(ctx, "ysk:card:upsert", map[string]string{"card:body": string(card)})
}

// Withdraw removes the card from the dashboards that are open right now.
func (n Notifier) Withdraw(ctx context.Context, e Entry) error {
	return n.publish(ctx, "ysk:card:delete", map[string]string{"card:id": CardID(e)})
}
