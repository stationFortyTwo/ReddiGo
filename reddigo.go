package reddigo

import (
	"bytes"
	jsonpkg "encoding/json"
	"fmt"
	"io"
	"net/http"
	urlpkg "net/url"
	"strings"
	"time"
)

type RedditConfig struct {
	ClientID     string
	ClientSecret string
	AccessToken  string
	RefreshToken string
	UserAgent    string
}

type ReddiGoSDK struct {
	clientID     string
	clientSecret string
	accessToken  string
	refreshToken string
	userAgent    string
	tokenExpiry  time.Time
	httpClient   *http.Client
}

func NewReddiGoSDK(config RedditConfig) *ReddiGoSDK {
	return &ReddiGoSDK{
		clientID:     config.ClientID,
		clientSecret: config.ClientSecret,
		accessToken:  config.AccessToken,
		refreshToken: config.RefreshToken,
		userAgent:    config.UserAgent,
		tokenExpiry:  time.Now(),
		httpClient:   &http.Client{},
	}
}

// Function to refresh the access token
func (sdk *ReddiGoSDK) refreshTokenIfNeeded() error {
	// Check if the token is close to expiration
	if time.Now().After(sdk.tokenExpiry) {
		url := "https://www.reddit.com/api/v1/access_token"
		data := urlpkg.Values{}
		data.Set("grant_type", "refresh_token")
		data.Set("refresh_token", sdk.refreshToken)

		req, err := http.NewRequest("POST", url, strings.NewReader(data.Encode()))

		if err != nil {
			return fmt.Errorf("failed to create new request: %w", err)
		}

		// Set Basic Authentication using client ID and client secret
		req.SetBasicAuth(sdk.clientID, sdk.clientSecret)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("User-Agent", sdk.userAgent)

		resp, err := sdk.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("request to refresh token failed: %w", err)
		}
		defer resp.Body.Close()

		// Check if the status code indicates success
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("failed to refresh token, status: %d, response: %s", resp.StatusCode, string(body))
		}

		// Parse the response JSON
		var result struct {
			AccessToken string `json:"access_token"`
			ExpiresIn   int    `json:"expires_in"`
		}
		if err := jsonpkg.NewDecoder(resp.Body).Decode(&result); err != nil {
			return fmt.Errorf("failed to decode response: %w", err)
		}

		// Check if access token is available in the response
		if result.AccessToken == "" {
			return fmt.Errorf("missing access token in response")
		}

		// Update the access token and expiry time
		sdk.accessToken = result.AccessToken
		sdk.tokenExpiry = time.Now().Add(time.Duration(result.ExpiresIn-60) * time.Second) // Set expiry 1 minute earlier for safety
	}
	return nil
}

func (sdk *ReddiGoSDK) MakeRequest(method, endpoint string, body io.Reader) (*http.Response, error) {
	url := fmt.Sprintf("https://oauth.reddit.com%s", endpoint)
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", sdk.accessToken))
	req.Header.Set("User-Agent", sdk.userAgent)

	resp, err := sdk.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	// If response indicates unauthorized (e.g., token issue), handle it
	if resp.StatusCode == http.StatusUnauthorized {
		// Retry token refresh and the request if the token was invalid
		if err := sdk.refreshTokenIfNeeded(); err != nil {
			return nil, fmt.Errorf("failed to refresh token on retry: %w", err)
		}

		// Retry the request with the refreshed token
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", sdk.accessToken))
		resp, err = sdk.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("retry request failed: %w", err)
		}
	}

	return resp, nil
}

/*
GetMe makes a GET request to /api/v1/me
ID: GET /api/v1/me
Description: Returns the identity of the user.
*/
func (sdk *ReddiGoSDK) GetMe() (any, error) {
	reqUrl := "/api/v1/me"
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
GetMeKarma makes a GET request to /api/v1/me/karma
ID: GET /api/v1/me/karma
Description: Return a breakdown of subreddit karma.
*/
func (sdk *ReddiGoSDK) GetMeKarma() (any, error) {
	reqUrl := "/api/v1/me/karma"
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

// GetMePrefsResponse represents the response for GET /api/v1/me/prefs
type GetMePrefsResponse struct {
	Fields string `json:"fields"` /* A comma-separated list of items from this set:beta
	threaded_messages
	hide_downs
	private_feeds
	activity_relevant_ads
	enable_reddit_pro_analytics_emails
	profile_opt_out
	bad_comment_autocollapse
	third_party_site_data_personalized_content
	show_link_flair
	live_bar_recommendations_enabled
	show_trending
	top_karma_subreddits
	country_code
	theme_selector
	monitor_mentions
	email_comment_reply
	newwindow
	email_new_user_welcome
	research
	ignore_suggested_sort
	show_presence
	email_upvote_comment
	email_digests
	whatsapp_comment_reply
	num_comments
	feed_recommendations_enabled
	clickgadget
	use_global_defaults
	label_nsfw
	domain_details
	show_stylesheets
	live_orangereds
	highlight_controversial
	mark_messages_read
	no_profanity
	email_unsubscribe_all
	whatsapp_enabled
	lang
	in_redesign_beta
	email_messages
	third_party_data_personalized_ads
	email_chat_request
	allow_clicktracking
	hide_from_robots
	show_gold_expiration
	show_twitter
	compress
	store_visits
	video_autoplay
	email_upvote_post
	email_username_mention
	media_preview
	email_user_new_follower
	nightmode
	enable_default_themes
	geopopular
	third_party_site_data_personalized_ads
	survey_last_seen_time
	threaded_modmail
	enable_followers
	hide_ups
	min_comment_score
	public_votes
	show_location_based_recommendations
	email_post_reply
	collapse_read_messages
	show_flair
	send_crosspost_messages
	search_include_over_18
	hide_ads
	third_party_personalized_ads
	min_link_score
	over_18
	sms_notifications_enabled
	numsites
	media
	legacy_search
	email_private_message
	send_welcome_messages
	email_community_discovery
	highlight_new_comments
	default_comment_sort
	accept_pms */
}

/*
GetMePrefs makes a GET request to /api/v1/me/prefs
ID: GET /api/v1/me/prefs
Description: Return the preference settings of the logged in user
*/
func (sdk *ReddiGoSDK) GetMePrefs() (GetMePrefsResponse, error) {
	reqUrl := "/api/v1/me/prefs"
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return GetMePrefsResponse{}, err
	}
	defer resp.Body.Close()
	var response GetMePrefsResponse
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return GetMePrefsResponse{}, err
	}
	return response, nil
}

type PatchMePrefsAcceptPmsEnum string

const (
	PatchMePrefsAcceptPmsEnumEveryone    PatchMePrefsAcceptPmsEnum = "everyone"
	PatchMePrefsAcceptPmsEnumWhitelisted PatchMePrefsAcceptPmsEnum = "whitelisted"
)

type PatchMePrefsBadCommentAutocollapseEnum string

const (
	PatchMePrefsBadCommentAutocollapseEnumOff    PatchMePrefsBadCommentAutocollapseEnum = "off"
	PatchMePrefsBadCommentAutocollapseEnumLow    PatchMePrefsBadCommentAutocollapseEnum = "low"
	PatchMePrefsBadCommentAutocollapseEnumMedium PatchMePrefsBadCommentAutocollapseEnum = "medium"
	PatchMePrefsBadCommentAutocollapseEnumHigh   PatchMePrefsBadCommentAutocollapseEnum = "high"
)

type PatchMePrefsCountryCodeEnum string

const (
	PatchMePrefsCountryCodeEnumWF PatchMePrefsCountryCodeEnum = "WF"
	PatchMePrefsCountryCodeEnumJP PatchMePrefsCountryCodeEnum = "JP"
	PatchMePrefsCountryCodeEnumJM PatchMePrefsCountryCodeEnum = "JM"
	PatchMePrefsCountryCodeEnumJO PatchMePrefsCountryCodeEnum = "JO"
	PatchMePrefsCountryCodeEnumWS PatchMePrefsCountryCodeEnum = "WS"
	PatchMePrefsCountryCodeEnumJE PatchMePrefsCountryCodeEnum = "JE"
	PatchMePrefsCountryCodeEnumGW PatchMePrefsCountryCodeEnum = "GW"
	PatchMePrefsCountryCodeEnumGU PatchMePrefsCountryCodeEnum = "GU"
	PatchMePrefsCountryCodeEnumGT PatchMePrefsCountryCodeEnum = "GT"
	PatchMePrefsCountryCodeEnumGS PatchMePrefsCountryCodeEnum = "GS"
	PatchMePrefsCountryCodeEnumGR PatchMePrefsCountryCodeEnum = "GR"
	PatchMePrefsCountryCodeEnumGQ PatchMePrefsCountryCodeEnum = "GQ"
	PatchMePrefsCountryCodeEnumGP PatchMePrefsCountryCodeEnum = "GP"
	PatchMePrefsCountryCodeEnumGY PatchMePrefsCountryCodeEnum = "GY"
	PatchMePrefsCountryCodeEnumGG PatchMePrefsCountryCodeEnum = "GG"
	PatchMePrefsCountryCodeEnumGF PatchMePrefsCountryCodeEnum = "GF"
	PatchMePrefsCountryCodeEnumGE PatchMePrefsCountryCodeEnum = "GE"
	PatchMePrefsCountryCodeEnumGD PatchMePrefsCountryCodeEnum = "GD"
	PatchMePrefsCountryCodeEnumGB PatchMePrefsCountryCodeEnum = "GB"
	PatchMePrefsCountryCodeEnumGA PatchMePrefsCountryCodeEnum = "GA"
	PatchMePrefsCountryCodeEnumGN PatchMePrefsCountryCodeEnum = "GN"
	PatchMePrefsCountryCodeEnumGM PatchMePrefsCountryCodeEnum = "GM"
	PatchMePrefsCountryCodeEnumGL PatchMePrefsCountryCodeEnum = "GL"
	PatchMePrefsCountryCodeEnumGI PatchMePrefsCountryCodeEnum = "GI"
	PatchMePrefsCountryCodeEnumGH PatchMePrefsCountryCodeEnum = "GH"
	PatchMePrefsCountryCodeEnumPR PatchMePrefsCountryCodeEnum = "PR"
	PatchMePrefsCountryCodeEnumPS PatchMePrefsCountryCodeEnum = "PS"
	PatchMePrefsCountryCodeEnumPW PatchMePrefsCountryCodeEnum = "PW"
	PatchMePrefsCountryCodeEnumPT PatchMePrefsCountryCodeEnum = "PT"
	PatchMePrefsCountryCodeEnumPY PatchMePrefsCountryCodeEnum = "PY"
	PatchMePrefsCountryCodeEnumPA PatchMePrefsCountryCodeEnum = "PA"
	PatchMePrefsCountryCodeEnumPF PatchMePrefsCountryCodeEnum = "PF"
	PatchMePrefsCountryCodeEnumPG PatchMePrefsCountryCodeEnum = "PG"
	PatchMePrefsCountryCodeEnumPE PatchMePrefsCountryCodeEnum = "PE"
	PatchMePrefsCountryCodeEnumPK PatchMePrefsCountryCodeEnum = "PK"
	PatchMePrefsCountryCodeEnumPH PatchMePrefsCountryCodeEnum = "PH"
	PatchMePrefsCountryCodeEnumPN PatchMePrefsCountryCodeEnum = "PN"
	PatchMePrefsCountryCodeEnumPL PatchMePrefsCountryCodeEnum = "PL"
	PatchMePrefsCountryCodeEnumPM PatchMePrefsCountryCodeEnum = "PM"
	PatchMePrefsCountryCodeEnumZM PatchMePrefsCountryCodeEnum = "ZM"
	PatchMePrefsCountryCodeEnumZA PatchMePrefsCountryCodeEnum = "ZA"
	PatchMePrefsCountryCodeEnumZZ PatchMePrefsCountryCodeEnum = "ZZ"
	PatchMePrefsCountryCodeEnumZW PatchMePrefsCountryCodeEnum = "ZW"
	PatchMePrefsCountryCodeEnumME PatchMePrefsCountryCodeEnum = "ME"
	PatchMePrefsCountryCodeEnumMD PatchMePrefsCountryCodeEnum = "MD"
	PatchMePrefsCountryCodeEnumMG PatchMePrefsCountryCodeEnum = "MG"
	PatchMePrefsCountryCodeEnumMF PatchMePrefsCountryCodeEnum = "MF"
	PatchMePrefsCountryCodeEnumMA PatchMePrefsCountryCodeEnum = "MA"
	PatchMePrefsCountryCodeEnumMC PatchMePrefsCountryCodeEnum = "MC"
	PatchMePrefsCountryCodeEnumMM PatchMePrefsCountryCodeEnum = "MM"
	PatchMePrefsCountryCodeEnumML PatchMePrefsCountryCodeEnum = "ML"
	PatchMePrefsCountryCodeEnumMO PatchMePrefsCountryCodeEnum = "MO"
	PatchMePrefsCountryCodeEnumMN PatchMePrefsCountryCodeEnum = "MN"
	PatchMePrefsCountryCodeEnumMH PatchMePrefsCountryCodeEnum = "MH"
	PatchMePrefsCountryCodeEnumMK PatchMePrefsCountryCodeEnum = "MK"
	PatchMePrefsCountryCodeEnumMU PatchMePrefsCountryCodeEnum = "MU"
	PatchMePrefsCountryCodeEnumMT PatchMePrefsCountryCodeEnum = "MT"
	PatchMePrefsCountryCodeEnumMW PatchMePrefsCountryCodeEnum = "MW"
	PatchMePrefsCountryCodeEnumMV PatchMePrefsCountryCodeEnum = "MV"
	PatchMePrefsCountryCodeEnumMQ PatchMePrefsCountryCodeEnum = "MQ"
	PatchMePrefsCountryCodeEnumMP PatchMePrefsCountryCodeEnum = "MP"
	PatchMePrefsCountryCodeEnumMS PatchMePrefsCountryCodeEnum = "MS"
	PatchMePrefsCountryCodeEnumMR PatchMePrefsCountryCodeEnum = "MR"
	PatchMePrefsCountryCodeEnumMY PatchMePrefsCountryCodeEnum = "MY"
	PatchMePrefsCountryCodeEnumMX PatchMePrefsCountryCodeEnum = "MX"
	PatchMePrefsCountryCodeEnumMZ PatchMePrefsCountryCodeEnum = "MZ"
	PatchMePrefsCountryCodeEnumFR PatchMePrefsCountryCodeEnum = "FR"
	PatchMePrefsCountryCodeEnumFI PatchMePrefsCountryCodeEnum = "FI"
	PatchMePrefsCountryCodeEnumFJ PatchMePrefsCountryCodeEnum = "FJ"
	PatchMePrefsCountryCodeEnumFK PatchMePrefsCountryCodeEnum = "FK"
	PatchMePrefsCountryCodeEnumFM PatchMePrefsCountryCodeEnum = "FM"
	PatchMePrefsCountryCodeEnumFO PatchMePrefsCountryCodeEnum = "FO"
	PatchMePrefsCountryCodeEnumCK PatchMePrefsCountryCodeEnum = "CK"
	PatchMePrefsCountryCodeEnumCI PatchMePrefsCountryCodeEnum = "CI"
	PatchMePrefsCountryCodeEnumCH PatchMePrefsCountryCodeEnum = "CH"
	PatchMePrefsCountryCodeEnumCO PatchMePrefsCountryCodeEnum = "CO"
	PatchMePrefsCountryCodeEnumCN PatchMePrefsCountryCodeEnum = "CN"
	PatchMePrefsCountryCodeEnumCM PatchMePrefsCountryCodeEnum = "CM"
	PatchMePrefsCountryCodeEnumCL PatchMePrefsCountryCodeEnum = "CL"
	PatchMePrefsCountryCodeEnumCC PatchMePrefsCountryCodeEnum = "CC"
	PatchMePrefsCountryCodeEnumCA PatchMePrefsCountryCodeEnum = "CA"
	PatchMePrefsCountryCodeEnumCG PatchMePrefsCountryCodeEnum = "CG"
	PatchMePrefsCountryCodeEnumCF PatchMePrefsCountryCodeEnum = "CF"
	PatchMePrefsCountryCodeEnumCD PatchMePrefsCountryCodeEnum = "CD"
	PatchMePrefsCountryCodeEnumCZ PatchMePrefsCountryCodeEnum = "CZ"
	PatchMePrefsCountryCodeEnumCY PatchMePrefsCountryCodeEnum = "CY"
	PatchMePrefsCountryCodeEnumCX PatchMePrefsCountryCodeEnum = "CX"
	PatchMePrefsCountryCodeEnumCR PatchMePrefsCountryCodeEnum = "CR"
	PatchMePrefsCountryCodeEnumCW PatchMePrefsCountryCodeEnum = "CW"
	PatchMePrefsCountryCodeEnumCV PatchMePrefsCountryCodeEnum = "CV"
	PatchMePrefsCountryCodeEnumCU PatchMePrefsCountryCodeEnum = "CU"
	PatchMePrefsCountryCodeEnumSZ PatchMePrefsCountryCodeEnum = "SZ"
	PatchMePrefsCountryCodeEnumSY PatchMePrefsCountryCodeEnum = "SY"
	PatchMePrefsCountryCodeEnumSX PatchMePrefsCountryCodeEnum = "SX"
	PatchMePrefsCountryCodeEnumSS PatchMePrefsCountryCodeEnum = "SS"
	PatchMePrefsCountryCodeEnumSR PatchMePrefsCountryCodeEnum = "SR"
	PatchMePrefsCountryCodeEnumSV PatchMePrefsCountryCodeEnum = "SV"
	PatchMePrefsCountryCodeEnumST PatchMePrefsCountryCodeEnum = "ST"
	PatchMePrefsCountryCodeEnumSK PatchMePrefsCountryCodeEnum = "SK"
	PatchMePrefsCountryCodeEnumSJ PatchMePrefsCountryCodeEnum = "SJ"
	PatchMePrefsCountryCodeEnumSI PatchMePrefsCountryCodeEnum = "SI"
	PatchMePrefsCountryCodeEnumSH PatchMePrefsCountryCodeEnum = "SH"
	PatchMePrefsCountryCodeEnumSO PatchMePrefsCountryCodeEnum = "SO"
	PatchMePrefsCountryCodeEnumSN PatchMePrefsCountryCodeEnum = "SN"
	PatchMePrefsCountryCodeEnumSM PatchMePrefsCountryCodeEnum = "SM"
	PatchMePrefsCountryCodeEnumSL PatchMePrefsCountryCodeEnum = "SL"
	PatchMePrefsCountryCodeEnumSC PatchMePrefsCountryCodeEnum = "SC"
	PatchMePrefsCountryCodeEnumSB PatchMePrefsCountryCodeEnum = "SB"
	PatchMePrefsCountryCodeEnumSA PatchMePrefsCountryCodeEnum = "SA"
	PatchMePrefsCountryCodeEnumSG PatchMePrefsCountryCodeEnum = "SG"
	PatchMePrefsCountryCodeEnumSE PatchMePrefsCountryCodeEnum = "SE"
	PatchMePrefsCountryCodeEnumSD PatchMePrefsCountryCodeEnum = "SD"
	PatchMePrefsCountryCodeEnumYE PatchMePrefsCountryCodeEnum = "YE"
	PatchMePrefsCountryCodeEnumYT PatchMePrefsCountryCodeEnum = "YT"
	PatchMePrefsCountryCodeEnumLB PatchMePrefsCountryCodeEnum = "LB"
	PatchMePrefsCountryCodeEnumLC PatchMePrefsCountryCodeEnum = "LC"
	PatchMePrefsCountryCodeEnumLA PatchMePrefsCountryCodeEnum = "LA"
	PatchMePrefsCountryCodeEnumLK PatchMePrefsCountryCodeEnum = "LK"
	PatchMePrefsCountryCodeEnumLI PatchMePrefsCountryCodeEnum = "LI"
	PatchMePrefsCountryCodeEnumLV PatchMePrefsCountryCodeEnum = "LV"
	PatchMePrefsCountryCodeEnumLT PatchMePrefsCountryCodeEnum = "LT"
	PatchMePrefsCountryCodeEnumLU PatchMePrefsCountryCodeEnum = "LU"
	PatchMePrefsCountryCodeEnumLR PatchMePrefsCountryCodeEnum = "LR"
	PatchMePrefsCountryCodeEnumLS PatchMePrefsCountryCodeEnum = "LS"
	PatchMePrefsCountryCodeEnumLY PatchMePrefsCountryCodeEnum = "LY"
	PatchMePrefsCountryCodeEnumVA PatchMePrefsCountryCodeEnum = "VA"
	PatchMePrefsCountryCodeEnumVC PatchMePrefsCountryCodeEnum = "VC"
	PatchMePrefsCountryCodeEnumVE PatchMePrefsCountryCodeEnum = "VE"
	PatchMePrefsCountryCodeEnumVG PatchMePrefsCountryCodeEnum = "VG"
	PatchMePrefsCountryCodeEnumIQ PatchMePrefsCountryCodeEnum = "IQ"
	PatchMePrefsCountryCodeEnumVI PatchMePrefsCountryCodeEnum = "VI"
	PatchMePrefsCountryCodeEnumIS PatchMePrefsCountryCodeEnum = "IS"
	PatchMePrefsCountryCodeEnumIR PatchMePrefsCountryCodeEnum = "IR"
	PatchMePrefsCountryCodeEnumIT PatchMePrefsCountryCodeEnum = "IT"
	PatchMePrefsCountryCodeEnumVN PatchMePrefsCountryCodeEnum = "VN"
	PatchMePrefsCountryCodeEnumIM PatchMePrefsCountryCodeEnum = "IM"
	PatchMePrefsCountryCodeEnumIL PatchMePrefsCountryCodeEnum = "IL"
	PatchMePrefsCountryCodeEnumIO PatchMePrefsCountryCodeEnum = "IO"
	PatchMePrefsCountryCodeEnumIN PatchMePrefsCountryCodeEnum = "IN"
	PatchMePrefsCountryCodeEnumIE PatchMePrefsCountryCodeEnum = "IE"
	PatchMePrefsCountryCodeEnumID PatchMePrefsCountryCodeEnum = "ID"
	PatchMePrefsCountryCodeEnumBD PatchMePrefsCountryCodeEnum = "BD"
	PatchMePrefsCountryCodeEnumBE PatchMePrefsCountryCodeEnum = "BE"
	PatchMePrefsCountryCodeEnumBF PatchMePrefsCountryCodeEnum = "BF"
	PatchMePrefsCountryCodeEnumBG PatchMePrefsCountryCodeEnum = "BG"
	PatchMePrefsCountryCodeEnumBA PatchMePrefsCountryCodeEnum = "BA"
	PatchMePrefsCountryCodeEnumBB PatchMePrefsCountryCodeEnum = "BB"
	PatchMePrefsCountryCodeEnumBL PatchMePrefsCountryCodeEnum = "BL"
	PatchMePrefsCountryCodeEnumBM PatchMePrefsCountryCodeEnum = "BM"
	PatchMePrefsCountryCodeEnumBN PatchMePrefsCountryCodeEnum = "BN"
	PatchMePrefsCountryCodeEnumBO PatchMePrefsCountryCodeEnum = "BO"
	PatchMePrefsCountryCodeEnumBH PatchMePrefsCountryCodeEnum = "BH"
	PatchMePrefsCountryCodeEnumBI PatchMePrefsCountryCodeEnum = "BI"
	PatchMePrefsCountryCodeEnumBJ PatchMePrefsCountryCodeEnum = "BJ"
	PatchMePrefsCountryCodeEnumBT PatchMePrefsCountryCodeEnum = "BT"
	PatchMePrefsCountryCodeEnumBV PatchMePrefsCountryCodeEnum = "BV"
	PatchMePrefsCountryCodeEnumBW PatchMePrefsCountryCodeEnum = "BW"
	PatchMePrefsCountryCodeEnumBQ PatchMePrefsCountryCodeEnum = "BQ"
	PatchMePrefsCountryCodeEnumBR PatchMePrefsCountryCodeEnum = "BR"
	PatchMePrefsCountryCodeEnumBS PatchMePrefsCountryCodeEnum = "BS"
	PatchMePrefsCountryCodeEnumBY PatchMePrefsCountryCodeEnum = "BY"
	PatchMePrefsCountryCodeEnumBZ PatchMePrefsCountryCodeEnum = "BZ"
	PatchMePrefsCountryCodeEnumRU PatchMePrefsCountryCodeEnum = "RU"
	PatchMePrefsCountryCodeEnumRW PatchMePrefsCountryCodeEnum = "RW"
	PatchMePrefsCountryCodeEnumRS PatchMePrefsCountryCodeEnum = "RS"
	PatchMePrefsCountryCodeEnumRE PatchMePrefsCountryCodeEnum = "RE"
	PatchMePrefsCountryCodeEnumRO PatchMePrefsCountryCodeEnum = "RO"
	PatchMePrefsCountryCodeEnumOM PatchMePrefsCountryCodeEnum = "OM"
	PatchMePrefsCountryCodeEnumHR PatchMePrefsCountryCodeEnum = "HR"
	PatchMePrefsCountryCodeEnumHT PatchMePrefsCountryCodeEnum = "HT"
	PatchMePrefsCountryCodeEnumHU PatchMePrefsCountryCodeEnum = "HU"
	PatchMePrefsCountryCodeEnumHK PatchMePrefsCountryCodeEnum = "HK"
	PatchMePrefsCountryCodeEnumHN PatchMePrefsCountryCodeEnum = "HN"
	PatchMePrefsCountryCodeEnumHM PatchMePrefsCountryCodeEnum = "HM"
	PatchMePrefsCountryCodeEnumEH PatchMePrefsCountryCodeEnum = "EH"
	PatchMePrefsCountryCodeEnumEE PatchMePrefsCountryCodeEnum = "EE"
	PatchMePrefsCountryCodeEnumEG PatchMePrefsCountryCodeEnum = "EG"
	PatchMePrefsCountryCodeEnumEC PatchMePrefsCountryCodeEnum = "EC"
	PatchMePrefsCountryCodeEnumET PatchMePrefsCountryCodeEnum = "ET"
	PatchMePrefsCountryCodeEnumES PatchMePrefsCountryCodeEnum = "ES"
	PatchMePrefsCountryCodeEnumER PatchMePrefsCountryCodeEnum = "ER"
	PatchMePrefsCountryCodeEnumUY PatchMePrefsCountryCodeEnum = "UY"
	PatchMePrefsCountryCodeEnumUZ PatchMePrefsCountryCodeEnum = "UZ"
	PatchMePrefsCountryCodeEnumUS PatchMePrefsCountryCodeEnum = "US"
	PatchMePrefsCountryCodeEnumUM PatchMePrefsCountryCodeEnum = "UM"
	PatchMePrefsCountryCodeEnumUG PatchMePrefsCountryCodeEnum = "UG"
	PatchMePrefsCountryCodeEnumUA PatchMePrefsCountryCodeEnum = "UA"
	PatchMePrefsCountryCodeEnumVU PatchMePrefsCountryCodeEnum = "VU"
	PatchMePrefsCountryCodeEnumNI PatchMePrefsCountryCodeEnum = "NI"
	PatchMePrefsCountryCodeEnumNL PatchMePrefsCountryCodeEnum = "NL"
	PatchMePrefsCountryCodeEnumNO PatchMePrefsCountryCodeEnum = "NO"
	PatchMePrefsCountryCodeEnumNA PatchMePrefsCountryCodeEnum = "NA"
	PatchMePrefsCountryCodeEnumNC PatchMePrefsCountryCodeEnum = "NC"
	PatchMePrefsCountryCodeEnumNE PatchMePrefsCountryCodeEnum = "NE"
	PatchMePrefsCountryCodeEnumNF PatchMePrefsCountryCodeEnum = "NF"
	PatchMePrefsCountryCodeEnumNG PatchMePrefsCountryCodeEnum = "NG"
	PatchMePrefsCountryCodeEnumNZ PatchMePrefsCountryCodeEnum = "NZ"
	PatchMePrefsCountryCodeEnumNP PatchMePrefsCountryCodeEnum = "NP"
	PatchMePrefsCountryCodeEnumNR PatchMePrefsCountryCodeEnum = "NR"
	PatchMePrefsCountryCodeEnumNU PatchMePrefsCountryCodeEnum = "NU"
	PatchMePrefsCountryCodeEnumXK PatchMePrefsCountryCodeEnum = "XK"
	PatchMePrefsCountryCodeEnumXZ PatchMePrefsCountryCodeEnum = "XZ"
	PatchMePrefsCountryCodeEnumXX PatchMePrefsCountryCodeEnum = "XX"
	PatchMePrefsCountryCodeEnumKG PatchMePrefsCountryCodeEnum = "KG"
	PatchMePrefsCountryCodeEnumKE PatchMePrefsCountryCodeEnum = "KE"
	PatchMePrefsCountryCodeEnumKI PatchMePrefsCountryCodeEnum = "KI"
	PatchMePrefsCountryCodeEnumKH PatchMePrefsCountryCodeEnum = "KH"
	PatchMePrefsCountryCodeEnumKN PatchMePrefsCountryCodeEnum = "KN"
	PatchMePrefsCountryCodeEnumKM PatchMePrefsCountryCodeEnum = "KM"
	PatchMePrefsCountryCodeEnumKR PatchMePrefsCountryCodeEnum = "KR"
	PatchMePrefsCountryCodeEnumKP PatchMePrefsCountryCodeEnum = "KP"
	PatchMePrefsCountryCodeEnumKW PatchMePrefsCountryCodeEnum = "KW"
	PatchMePrefsCountryCodeEnumKZ PatchMePrefsCountryCodeEnum = "KZ"
	PatchMePrefsCountryCodeEnumKY PatchMePrefsCountryCodeEnum = "KY"
	PatchMePrefsCountryCodeEnumDO PatchMePrefsCountryCodeEnum = "DO"
	PatchMePrefsCountryCodeEnumDM PatchMePrefsCountryCodeEnum = "DM"
	PatchMePrefsCountryCodeEnumDJ PatchMePrefsCountryCodeEnum = "DJ"
	PatchMePrefsCountryCodeEnumDK PatchMePrefsCountryCodeEnum = "DK"
	PatchMePrefsCountryCodeEnumDE PatchMePrefsCountryCodeEnum = "DE"
	PatchMePrefsCountryCodeEnumDZ PatchMePrefsCountryCodeEnum = "DZ"
	PatchMePrefsCountryCodeEnumTZ PatchMePrefsCountryCodeEnum = "TZ"
	PatchMePrefsCountryCodeEnumTV PatchMePrefsCountryCodeEnum = "TV"
	PatchMePrefsCountryCodeEnumTW PatchMePrefsCountryCodeEnum = "TW"
	PatchMePrefsCountryCodeEnumTT PatchMePrefsCountryCodeEnum = "TT"
	PatchMePrefsCountryCodeEnumTR PatchMePrefsCountryCodeEnum = "TR"
	PatchMePrefsCountryCodeEnumTN PatchMePrefsCountryCodeEnum = "TN"
	PatchMePrefsCountryCodeEnumTO PatchMePrefsCountryCodeEnum = "TO"
	PatchMePrefsCountryCodeEnumTL PatchMePrefsCountryCodeEnum = "TL"
	PatchMePrefsCountryCodeEnumTM PatchMePrefsCountryCodeEnum = "TM"
	PatchMePrefsCountryCodeEnumTJ PatchMePrefsCountryCodeEnum = "TJ"
	PatchMePrefsCountryCodeEnumTK PatchMePrefsCountryCodeEnum = "TK"
	PatchMePrefsCountryCodeEnumTH PatchMePrefsCountryCodeEnum = "TH"
	PatchMePrefsCountryCodeEnumTF PatchMePrefsCountryCodeEnum = "TF"
	PatchMePrefsCountryCodeEnumTG PatchMePrefsCountryCodeEnum = "TG"
	PatchMePrefsCountryCodeEnumTD PatchMePrefsCountryCodeEnum = "TD"
	PatchMePrefsCountryCodeEnumTC PatchMePrefsCountryCodeEnum = "TC"
	PatchMePrefsCountryCodeEnumAE PatchMePrefsCountryCodeEnum = "AE"
	PatchMePrefsCountryCodeEnumAD PatchMePrefsCountryCodeEnum = "AD"
	PatchMePrefsCountryCodeEnumAG PatchMePrefsCountryCodeEnum = "AG"
	PatchMePrefsCountryCodeEnumAF PatchMePrefsCountryCodeEnum = "AF"
	PatchMePrefsCountryCodeEnumAI PatchMePrefsCountryCodeEnum = "AI"
	PatchMePrefsCountryCodeEnumAM PatchMePrefsCountryCodeEnum = "AM"
	PatchMePrefsCountryCodeEnumAL PatchMePrefsCountryCodeEnum = "AL"
	PatchMePrefsCountryCodeEnumAO PatchMePrefsCountryCodeEnum = "AO"
	PatchMePrefsCountryCodeEnumAN PatchMePrefsCountryCodeEnum = "AN"
	PatchMePrefsCountryCodeEnumAQ PatchMePrefsCountryCodeEnum = "AQ"
	PatchMePrefsCountryCodeEnumAS PatchMePrefsCountryCodeEnum = "AS"
	PatchMePrefsCountryCodeEnumAR PatchMePrefsCountryCodeEnum = "AR"
	PatchMePrefsCountryCodeEnumAU PatchMePrefsCountryCodeEnum = "AU"
	PatchMePrefsCountryCodeEnumAT PatchMePrefsCountryCodeEnum = "AT"
	PatchMePrefsCountryCodeEnumAW PatchMePrefsCountryCodeEnum = "AW"
	PatchMePrefsCountryCodeEnumAX PatchMePrefsCountryCodeEnum = "AX"
	PatchMePrefsCountryCodeEnumAZ PatchMePrefsCountryCodeEnum = "AZ"
	PatchMePrefsCountryCodeEnumQA PatchMePrefsCountryCodeEnum = "QA"
)

type PatchMePrefsDefaultCommentSortEnum string

const (
	PatchMePrefsDefaultCommentSortEnumConfidence    PatchMePrefsDefaultCommentSortEnum = "confidence"
	PatchMePrefsDefaultCommentSortEnumTop           PatchMePrefsDefaultCommentSortEnum = "top"
	PatchMePrefsDefaultCommentSortEnumNew           PatchMePrefsDefaultCommentSortEnum = "new"
	PatchMePrefsDefaultCommentSortEnumControversial PatchMePrefsDefaultCommentSortEnum = "controversial"
	PatchMePrefsDefaultCommentSortEnumOld           PatchMePrefsDefaultCommentSortEnum = "old"
	PatchMePrefsDefaultCommentSortEnumRandom        PatchMePrefsDefaultCommentSortEnum = "random"
	PatchMePrefsDefaultCommentSortEnumQa            PatchMePrefsDefaultCommentSortEnum = "qa"
	PatchMePrefsDefaultCommentSortEnumLive          PatchMePrefsDefaultCommentSortEnum = "live"
)

type PatchMePrefsGEnum string

const (
	PatchMePrefsGEnumGLOBAL PatchMePrefsGEnum = "GLOBAL"
	PatchMePrefsGEnumUS     PatchMePrefsGEnum = "US"
	PatchMePrefsGEnumAR     PatchMePrefsGEnum = "AR"
	PatchMePrefsGEnumAU     PatchMePrefsGEnum = "AU"
	PatchMePrefsGEnumBG     PatchMePrefsGEnum = "BG"
	PatchMePrefsGEnumCA     PatchMePrefsGEnum = "CA"
	PatchMePrefsGEnumCL     PatchMePrefsGEnum = "CL"
	PatchMePrefsGEnumCO     PatchMePrefsGEnum = "CO"
	PatchMePrefsGEnumHR     PatchMePrefsGEnum = "HR"
	PatchMePrefsGEnumCZ     PatchMePrefsGEnum = "CZ"
	PatchMePrefsGEnumFI     PatchMePrefsGEnum = "FI"
	PatchMePrefsGEnumFR     PatchMePrefsGEnum = "FR"
	PatchMePrefsGEnumDE     PatchMePrefsGEnum = "DE"
	PatchMePrefsGEnumGR     PatchMePrefsGEnum = "GR"
	PatchMePrefsGEnumHU     PatchMePrefsGEnum = "HU"
	PatchMePrefsGEnumIS     PatchMePrefsGEnum = "IS"
	PatchMePrefsGEnumIN     PatchMePrefsGEnum = "IN"
	PatchMePrefsGEnumIE     PatchMePrefsGEnum = "IE"
	PatchMePrefsGEnumIT     PatchMePrefsGEnum = "IT"
	PatchMePrefsGEnumJP     PatchMePrefsGEnum = "JP"
	PatchMePrefsGEnumMY     PatchMePrefsGEnum = "MY"
	PatchMePrefsGEnumMX     PatchMePrefsGEnum = "MX"
	PatchMePrefsGEnumNZ     PatchMePrefsGEnum = "NZ"
	PatchMePrefsGEnumPH     PatchMePrefsGEnum = "PH"
	PatchMePrefsGEnumPL     PatchMePrefsGEnum = "PL"
	PatchMePrefsGEnumPT     PatchMePrefsGEnum = "PT"
	PatchMePrefsGEnumPR     PatchMePrefsGEnum = "PR"
	PatchMePrefsGEnumRO     PatchMePrefsGEnum = "RO"
	PatchMePrefsGEnumRS     PatchMePrefsGEnum = "RS"
	PatchMePrefsGEnumSG     PatchMePrefsGEnum = "SG"
	PatchMePrefsGEnumES     PatchMePrefsGEnum = "ES"
	PatchMePrefsGEnumSE     PatchMePrefsGEnum = "SE"
	PatchMePrefsGEnumTW     PatchMePrefsGEnum = "TW"
	PatchMePrefsGEnumTH     PatchMePrefsGEnum = "TH"
	PatchMePrefsGEnumTR     PatchMePrefsGEnum = "TR"
	PatchMePrefsGEnumGB     PatchMePrefsGEnum = "GB"
	PatchMePrefsGEnumUS_WA  PatchMePrefsGEnum = "US_WA"
	PatchMePrefsGEnumUS_DE  PatchMePrefsGEnum = "US_DE"
	PatchMePrefsGEnumUS_DC  PatchMePrefsGEnum = "US_DC"
	PatchMePrefsGEnumUS_WI  PatchMePrefsGEnum = "US_WI"
	PatchMePrefsGEnumUS_WV  PatchMePrefsGEnum = "US_WV"
	PatchMePrefsGEnumUS_HI  PatchMePrefsGEnum = "US_HI"
	PatchMePrefsGEnumUS_FL  PatchMePrefsGEnum = "US_FL"
	PatchMePrefsGEnumUS_WY  PatchMePrefsGEnum = "US_WY"
	PatchMePrefsGEnumUS_NH  PatchMePrefsGEnum = "US_NH"
	PatchMePrefsGEnumUS_NJ  PatchMePrefsGEnum = "US_NJ"
	PatchMePrefsGEnumUS_NM  PatchMePrefsGEnum = "US_NM"
	PatchMePrefsGEnumUS_TX  PatchMePrefsGEnum = "US_TX"
	PatchMePrefsGEnumUS_LA  PatchMePrefsGEnum = "US_LA"
	PatchMePrefsGEnumUS_NC  PatchMePrefsGEnum = "US_NC"
	PatchMePrefsGEnumUS_ND  PatchMePrefsGEnum = "US_ND"
	PatchMePrefsGEnumUS_NE  PatchMePrefsGEnum = "US_NE"
	PatchMePrefsGEnumUS_TN  PatchMePrefsGEnum = "US_TN"
	PatchMePrefsGEnumUS_NY  PatchMePrefsGEnum = "US_NY"
	PatchMePrefsGEnumUS_PA  PatchMePrefsGEnum = "US_PA"
	PatchMePrefsGEnumUS_CA  PatchMePrefsGEnum = "US_CA"
	PatchMePrefsGEnumUS_NV  PatchMePrefsGEnum = "US_NV"
	PatchMePrefsGEnumUS_VA  PatchMePrefsGEnum = "US_VA"
	PatchMePrefsGEnumUS_CO  PatchMePrefsGEnum = "US_CO"
	PatchMePrefsGEnumUS_AK  PatchMePrefsGEnum = "US_AK"
	PatchMePrefsGEnumUS_AL  PatchMePrefsGEnum = "US_AL"
	PatchMePrefsGEnumUS_AR  PatchMePrefsGEnum = "US_AR"
	PatchMePrefsGEnumUS_VT  PatchMePrefsGEnum = "US_VT"
	PatchMePrefsGEnumUS_IL  PatchMePrefsGEnum = "US_IL"
	PatchMePrefsGEnumUS_GA  PatchMePrefsGEnum = "US_GA"
	PatchMePrefsGEnumUS_IN  PatchMePrefsGEnum = "US_IN"
	PatchMePrefsGEnumUS_IA  PatchMePrefsGEnum = "US_IA"
	PatchMePrefsGEnumUS_OK  PatchMePrefsGEnum = "US_OK"
	PatchMePrefsGEnumUS_AZ  PatchMePrefsGEnum = "US_AZ"
	PatchMePrefsGEnumUS_ID  PatchMePrefsGEnum = "US_ID"
	PatchMePrefsGEnumUS_CT  PatchMePrefsGEnum = "US_CT"
	PatchMePrefsGEnumUS_ME  PatchMePrefsGEnum = "US_ME"
	PatchMePrefsGEnumUS_MD  PatchMePrefsGEnum = "US_MD"
	PatchMePrefsGEnumUS_MA  PatchMePrefsGEnum = "US_MA"
	PatchMePrefsGEnumUS_OH  PatchMePrefsGEnum = "US_OH"
	PatchMePrefsGEnumUS_UT  PatchMePrefsGEnum = "US_UT"
	PatchMePrefsGEnumUS_MO  PatchMePrefsGEnum = "US_MO"
	PatchMePrefsGEnumUS_MN  PatchMePrefsGEnum = "US_MN"
	PatchMePrefsGEnumUS_MI  PatchMePrefsGEnum = "US_MI"
	PatchMePrefsGEnumUS_RI  PatchMePrefsGEnum = "US_RI"
	PatchMePrefsGEnumUS_KS  PatchMePrefsGEnum = "US_KS"
	PatchMePrefsGEnumUS_MT  PatchMePrefsGEnum = "US_MT"
	PatchMePrefsGEnumUS_MS  PatchMePrefsGEnum = "US_MS"
	PatchMePrefsGEnumUS_SC  PatchMePrefsGEnum = "US_SC"
	PatchMePrefsGEnumUS_KY  PatchMePrefsGEnum = "US_KY"
	PatchMePrefsGEnumUS_OR  PatchMePrefsGEnum = "US_OR"
	PatchMePrefsGEnumUS_SD  PatchMePrefsGEnum = "US_SD"
)

type PatchMePrefsMediaEnum string

const (
	PatchMePrefsMediaEnumOn        PatchMePrefsMediaEnum = "on"
	PatchMePrefsMediaEnumOff       PatchMePrefsMediaEnum = "off"
	PatchMePrefsMediaEnumSubreddit PatchMePrefsMediaEnum = "subreddit"
)

type PatchMePrefsMediaPreviewEnum string

const (
	PatchMePrefsMediaPreviewEnumOn        PatchMePrefsMediaPreviewEnum = "on"
	PatchMePrefsMediaPreviewEnumOff       PatchMePrefsMediaPreviewEnum = "off"
	PatchMePrefsMediaPreviewEnumSubreddit PatchMePrefsMediaPreviewEnum = "subreddit"
)

/*
PatchMePrefs makes a PATCH request to /api/v1/me/prefs
ID: PATCH /api/v1/me/prefs
Description: No description available
*/
func (sdk *ReddiGoSDK) PatchMePrefs(acceptPms string, activityRelevantAds bool, allowClicktracking bool, badCommentAutocollapse string, beta bool, clickgadget bool, collapseReadMessages bool, compress bool, countryCode string, defaultCommentSort string, domainDetails bool, emailChatRequest bool, emailCommentReply bool, emailCommunityDiscovery bool, emailDigests bool, emailMessages bool, emailNewUserWelcome bool, emailPostReply bool, emailPrivateMessage bool, emailUnsubscribeAll bool, emailUpvoteComment bool, emailUpvotePost bool, emailUserNewFollower bool, emailUsernameMention bool, enableDefaultThemes bool, enableFollowers bool, enableRedditProAnalyticsEmails bool, feedRecommendationsEnabled bool, g string, hideAds bool, hideDowns bool, hideFromRobots bool, hideUps bool, highlightControversial bool, highlightNewComments bool, ignoreSuggestedSort bool, inRedesignBeta bool, labelNsfw bool, lang interface{}, legacySearch bool, liveBarRecommendationsEnabled bool, liveOrangereds bool, markMessagesRead bool, media string, mediaPreview string, minCommentScore int, minLinkScore int, monitorMentions bool, newwindow bool, nightmode bool, noProfanity bool, numComments int, numsites int, over18 bool, privateFeeds bool, profileOptOut bool, publicVotes bool, research bool, searchIncludeOver18 bool, sendCrosspostMessages bool, sendWelcomeMessages bool, showFlair bool, showGoldExpiration bool, showLinkFlair bool, showLocationBasedRecommendations bool, showPresence bool, showStylesheets bool, showTrending bool, showTwitter bool, smsNotificationsEnabled bool, storeVisits bool, surveyLastSeenTime int, themeSelector interface{}, thirdPartyDataPersonalizedAds bool, thirdPartyPersonalizedAds bool, thirdPartySiteDataPersonalizedAds bool, thirdPartySiteDataPersonalizedContent bool, threadedMessages bool, threadedModmail bool, topKarmaSubreddits bool, useGlobalDefaults bool, videoAutoplay bool, whatsappCommentReply bool, whatsappEnabled bool) (any, error) {
	reqUrl := "/api/v1/me/prefs"
	payload := map[string]interface{}{
		"accept_pms":                             acceptPms,
		"activity_relevant_ads":                  activityRelevantAds,
		"allow_clicktracking":                    allowClicktracking,
		"bad_comment_autocollapse":               badCommentAutocollapse,
		"beta":                                   beta,
		"clickgadget":                            clickgadget,
		"collapse_read_messages":                 collapseReadMessages,
		"compress":                               compress,
		"country_code":                           countryCode,
		"default_comment_sort":                   defaultCommentSort,
		"domain_details":                         domainDetails,
		"email_chat_request":                     emailChatRequest,
		"email_comment_reply":                    emailCommentReply,
		"email_community_discovery":              emailCommunityDiscovery,
		"email_digests":                          emailDigests,
		"email_messages":                         emailMessages,
		"email_new_user_welcome":                 emailNewUserWelcome,
		"email_post_reply":                       emailPostReply,
		"email_private_message":                  emailPrivateMessage,
		"email_unsubscribe_all":                  emailUnsubscribeAll,
		"email_upvote_comment":                   emailUpvoteComment,
		"email_upvote_post":                      emailUpvotePost,
		"email_user_new_follower":                emailUserNewFollower,
		"email_username_mention":                 emailUsernameMention,
		"enable_default_themes":                  enableDefaultThemes,
		"enable_followers":                       enableFollowers,
		"enable_reddit_pro_analytics_emails":     enableRedditProAnalyticsEmails,
		"feed_recommendations_enabled":           feedRecommendationsEnabled,
		"g":                                      g,
		"hide_ads":                               hideAds,
		"hide_downs":                             hideDowns,
		"hide_from_robots":                       hideFromRobots,
		"hide_ups":                               hideUps,
		"highlight_controversial":                highlightControversial,
		"highlight_new_comments":                 highlightNewComments,
		"ignore_suggested_sort":                  ignoreSuggestedSort,
		"in_redesign_beta":                       inRedesignBeta,
		"label_nsfw":                             labelNsfw,
		"lang":                                   lang,
		"legacy_search":                          legacySearch,
		"live_bar_recommendations_enabled":       liveBarRecommendationsEnabled,
		"live_orangereds":                        liveOrangereds,
		"mark_messages_read":                     markMessagesRead,
		"media":                                  media,
		"media_preview":                          mediaPreview,
		"min_comment_score":                      minCommentScore,
		"min_link_score":                         minLinkScore,
		"monitor_mentions":                       monitorMentions,
		"newwindow":                              newwindow,
		"nightmode":                              nightmode,
		"no_profanity":                           noProfanity,
		"num_comments":                           numComments,
		"numsites":                               numsites,
		"over_18":                                over18,
		"private_feeds":                          privateFeeds,
		"profile_opt_out":                        profileOptOut,
		"public_votes":                           publicVotes,
		"research":                               research,
		"search_include_over_18":                 searchIncludeOver18,
		"send_crosspost_messages":                sendCrosspostMessages,
		"send_welcome_messages":                  sendWelcomeMessages,
		"show_flair":                             showFlair,
		"show_gold_expiration":                   showGoldExpiration,
		"show_link_flair":                        showLinkFlair,
		"show_location_based_recommendations":    showLocationBasedRecommendations,
		"show_presence":                          showPresence,
		"show_stylesheets":                       showStylesheets,
		"show_trending":                          showTrending,
		"show_twitter":                           showTwitter,
		"sms_notifications_enabled":              smsNotificationsEnabled,
		"store_visits":                           storeVisits,
		"survey_last_seen_time":                  surveyLastSeenTime,
		"theme_selector":                         themeSelector,
		"third_party_data_personalized_ads":      thirdPartyDataPersonalizedAds,
		"third_party_personalized_ads":           thirdPartyPersonalizedAds,
		"third_party_site_data_personalized_ads": thirdPartySiteDataPersonalizedAds,
		"third_party_site_data_personalized_content": thirdPartySiteDataPersonalizedContent,
		"threaded_messages":                          threadedMessages,
		"threaded_modmail":                           threadedModmail,
		"top_karma_subreddits":                       topKarmaSubreddits,
		"use_global_defaults":                        useGlobalDefaults,
		"video_autoplay":                             videoAutoplay,
		"whatsapp_comment_reply":                     whatsappCommentReply,
		"whatsapp_enabled":                           whatsappEnabled,
	}
	// Construct the request for PATCH method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("PATCH", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
GetMeTrophies makes a GET request to /api/v1/me/trophies
ID: GET /api/v1/me/trophies
Description: Return a list of trophies for the current user.
*/
func (sdk *ReddiGoSDK) GetMeTrophies() (any, error) {
	reqUrl := "/api/v1/me/trophies"
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

// GetPrefsWhereResponse represents the response for GET /prefs/{where}
type GetPrefsWhereResponse struct {
	After    string      `json:"after"`     // fullname of a thing
	Before   string      `json:"before"`    // fullname of a thing
	Count    int         `json:"count"`     // a positive integer (default: 0)
	Limit    interface{} `json:"limit"`     // the maximum number of items desired (default: 25, maximum: 100)
	Show     string      `json:"show"`      // (optional) the string all
	SrDetail bool        `json:"sr_detail"` // (optional) expand subreddits
}

/*
GetPrefsWhere makes a GET request to /prefs/{where}
ID: GET /prefs/{where}
Description: This endpoint is a listing.
*/
func (sdk *ReddiGoSDK) GetPrefsWhere(where string, after string, before string, count string, limit string) (GetPrefsWhereResponse, error) {
	reqUrl := fmt.Sprintf("/prefs/%s", where)
	queryParams := urlpkg.Values{}
	queryParams.Add("after", after)
	queryParams.Add("before", before)
	queryParams.Add("count", count)
	queryParams.Add("limit", limit)
	reqUrl += "?" + queryParams.Encode()
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return GetPrefsWhereResponse{}, err
	}
	defer resp.Body.Close()
	var response GetPrefsWhereResponse
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return GetPrefsWhereResponse{}, err
	}
	return response, nil
}

/*
GetNeedsCaptcha makes a GET request to /api/needs_captcha
ID: GET /api/needs_captcha
Description: Check whether ReCAPTCHAs are needed for API methods
*/
func (sdk *ReddiGoSDK) GetNeedsCaptcha() (any, error) {
	reqUrl := "/api/needs_captcha"
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostCollectionsAddPostToCollection makes a POST request to /api/v1/collections/add_post_to_collection
ID: POST /api/v1/collections/add_post_to_collection
Description: Add a post to a collection
*/
func (sdk *ReddiGoSDK) PostCollectionsAddPostToCollection(collectionId interface{}, linkFullname string) (any, error) {
	reqUrl := "/api/v1/collections/add_post_to_collection"
	payload := map[string]interface{}{
		"collection_id": collectionId,
		"link_fullname": linkFullname,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

// GetCollectionsCollectionResponse represents the response for GET /api/v1/collections/collection
type GetCollectionsCollectionResponse struct {
	CollectionId interface{} `json:"collection_id"` // the UUID of a collection
	IncludeLinks bool        `json:"include_links"` // boolean value
}

/*
GetCollectionsCollection makes a GET request to /api/v1/collections/collection
ID: GET /api/v1/collections/collection
Description: Fetch a collection including all the links
*/
func (sdk *ReddiGoSDK) GetCollectionsCollection() (GetCollectionsCollectionResponse, error) {
	reqUrl := "/api/v1/collections/collection"
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return GetCollectionsCollectionResponse{}, err
	}
	defer resp.Body.Close()
	var response GetCollectionsCollectionResponse
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return GetCollectionsCollectionResponse{}, err
	}
	return response, nil
}

type PostCollectionsCreateCollectionDisplayLayoutEnum string

const (
	PostCollectionsCreateCollectionDisplayLayoutEnumTIMELINE PostCollectionsCreateCollectionDisplayLayoutEnum = "TIMELINE"
	PostCollectionsCreateCollectionDisplayLayoutEnumGALLERY  PostCollectionsCreateCollectionDisplayLayoutEnum = "GALLERY"
)

/*
PostCollectionsCreateCollection makes a POST request to /api/v1/collections/create_collection
ID: POST /api/v1/collections/create_collection
Description: Create a collection
*/
func (sdk *ReddiGoSDK) PostCollectionsCreateCollection(description string, displayLayout string, srFullname string, title string) (any, error) {
	reqUrl := "/api/v1/collections/create_collection"
	payload := map[string]interface{}{
		"description":    description,
		"display_layout": displayLayout,
		"sr_fullname":    srFullname,
		"title":          title,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostCollectionsDeleteCollection makes a POST request to /api/v1/collections/delete_collection
ID: POST /api/v1/collections/delete_collection
Description: Delete a collection
*/
func (sdk *ReddiGoSDK) PostCollectionsDeleteCollection(collectionId interface{}) (any, error) {
	reqUrl := "/api/v1/collections/delete_collection"
	payload := map[string]interface{}{
		"collection_id": collectionId,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostCollectionsFollowCollection makes a POST request to /api/v1/collections/follow_collection
ID: POST /api/v1/collections/follow_collection
Description: Follow or unfollow a collectionTo follow, follow should be True. To unfollow, follow should
be False. The user must have access to the subreddit to be able to
follow a collection within it.
*/
func (sdk *ReddiGoSDK) PostCollectionsFollowCollection(collectionId interface{}, follow bool) (any, error) {
	reqUrl := "/api/v1/collections/follow_collection"
	payload := map[string]interface{}{
		"collection_id": collectionId,
		"follow":        follow,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostCollectionsRemovePostInCollection makes a POST request to /api/v1/collections/remove_post_in_collection
ID: POST /api/v1/collections/remove_post_in_collection
Description: Remove a post from a collection
*/
func (sdk *ReddiGoSDK) PostCollectionsRemovePostInCollection(collectionId interface{}, linkFullname string) (any, error) {
	reqUrl := "/api/v1/collections/remove_post_in_collection"
	payload := map[string]interface{}{
		"collection_id": collectionId,
		"link_fullname": linkFullname,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostCollectionsReorderCollection makes a POST request to /api/v1/collections/reorder_collection
ID: POST /api/v1/collections/reorder_collection
Description: Reorder posts in a collection
*/
func (sdk *ReddiGoSDK) PostCollectionsReorderCollection(collectionId interface{}, linkIds interface{}) (any, error) {
	reqUrl := "/api/v1/collections/reorder_collection"
	payload := map[string]interface{}{
		"collection_id": collectionId,
		"link_ids":      linkIds,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

// GetCollectionsSubredditCollectionsResponse represents the response for GET /api/v1/collections/subreddit_collections
type GetCollectionsSubredditCollectionsResponse struct {
	SrFullname string `json:"sr_fullname"` // a fullname of a subreddit
}

/*
GetCollectionsSubredditCollections makes a GET request to /api/v1/collections/subreddit_collections
ID: GET /api/v1/collections/subreddit_collections
Description: Fetch collections for the subreddit
*/
func (sdk *ReddiGoSDK) GetCollectionsSubredditCollections() (GetCollectionsSubredditCollectionsResponse, error) {
	reqUrl := "/api/v1/collections/subreddit_collections"
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return GetCollectionsSubredditCollectionsResponse{}, err
	}
	defer resp.Body.Close()
	var response GetCollectionsSubredditCollectionsResponse
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return GetCollectionsSubredditCollectionsResponse{}, err
	}
	return response, nil
}

/*
PostCollectionsUpdateCollectionDescription makes a POST request to /api/v1/collections/update_collection_description
ID: POST /api/v1/collections/update_collection_description
Description: Update a collection's description
*/
func (sdk *ReddiGoSDK) PostCollectionsUpdateCollectionDescription(collectionId interface{}, description string) (any, error) {
	reqUrl := "/api/v1/collections/update_collection_description"
	payload := map[string]interface{}{
		"collection_id": collectionId,
		"description":   description,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

type PostCollectionsUpdateCollectionDisplayLayoutDisplayLayoutEnum string

const (
	PostCollectionsUpdateCollectionDisplayLayoutDisplayLayoutEnumTIMELINE PostCollectionsUpdateCollectionDisplayLayoutDisplayLayoutEnum = "TIMELINE"
	PostCollectionsUpdateCollectionDisplayLayoutDisplayLayoutEnumGALLERY  PostCollectionsUpdateCollectionDisplayLayoutDisplayLayoutEnum = "GALLERY"
)

/*
PostCollectionsUpdateCollectionDisplayLayout makes a POST request to /api/v1/collections/update_collection_display_layout
ID: POST /api/v1/collections/update_collection_display_layout
Description: Update a collection's display layout
*/
func (sdk *ReddiGoSDK) PostCollectionsUpdateCollectionDisplayLayout(collectionId interface{}, displayLayout string) (any, error) {
	reqUrl := "/api/v1/collections/update_collection_display_layout"
	payload := map[string]interface{}{
		"collection_id":  collectionId,
		"display_layout": displayLayout,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostCollectionsUpdateCollectionTitle makes a POST request to /api/v1/collections/update_collection_title
ID: POST /api/v1/collections/update_collection_title
Description: Update a collection's title
*/
func (sdk *ReddiGoSDK) PostCollectionsUpdateCollectionTitle(collectionId interface{}, title string) (any, error) {
	reqUrl := "/api/v1/collections/update_collection_title"
	payload := map[string]interface{}{
		"collection_id": collectionId,
		"title":         title,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostSubredditEmojiDotjson makes a POST request to /api/v1/{subreddit}/emoji.json
ID: POST /api/v1/{subreddit}/emoji.json
Description: Add an emoji to the DB by posting a message on emoji_upload_q.
A job processor that listens on a queue, uses the s3_key provided
in the request to locate the image in S3 Temp Bucket and moves it
to the PERM bucket. It also adds it to the DB using name as the column
and sr_fullname as the key and sends the status on the websocket URL
that is provided as part of this response.This endpoint should also be used to update custom subreddit emojis
with new images. If only the permissions on an emoji require updating
the POST_emoji_permissions endpoint should be requested, instead.
*/
func (sdk *ReddiGoSDK) PostSubredditEmojiDotjson(subreddit string, modFlairOnly bool, name string, postFlairAllowed bool, s3Key interface{}, userFlairAllowed bool) (any, error) {
	reqUrl := fmt.Sprintf("/api/v1/%s/emoji.json", subreddit)
	payload := map[string]interface{}{
		"mod_flair_only":     modFlairOnly,
		"name":               name,
		"post_flair_allowed": postFlairAllowed,
		"s3_key":             s3Key,
		"user_flair_allowed": userFlairAllowed,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
DeleteSubredditEmojiEmojiName makes a DELETE request to /api/v1/{subreddit}/emoji/{emoji_name}
ID: DELETE /api/v1/{subreddit}/emoji/{emoji_name}
Description: Delete a Subreddit emoji.
Remove the emoji from Cassandra and purge the assets from S3
and the image resizing provider.
*/
func (sdk *ReddiGoSDK) DeleteSubredditEmojiEmojiName(subreddit string, emojiName string) (any, error) {
	reqUrl := fmt.Sprintf("/api/v1/%s/emoji/%s", subreddit, emojiName)
	// Construct the request for DELETE method
	resp, err := sdk.MakeRequest("DELETE", reqUrl, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostSubredditEmojiAssetUploadS3Dotjson makes a POST request to /api/v1/{subreddit}/emoji_asset_upload_s3.json
ID: POST /api/v1/{subreddit}/emoji_asset_upload_s3.json
Description: Acquire and return an upload lease to s3 temp bucket. The return value
of this function is a json object containing credentials for uploading
assets to S3 bucket, S3 url for upload request and the key to use for
uploading. Using this lease the client will upload the emoji image to
S3 temp bucket (included as part of the S3 URL).This lease is used by S3 to verify that the upload is authorized.
*/
func (sdk *ReddiGoSDK) PostSubredditEmojiAssetUploadS3Dotjson(subreddit string, filepath interface{}, mimetype interface{}) (any, error) {
	reqUrl := fmt.Sprintf("/api/v1/%s/emoji_asset_upload_s3.json", subreddit)
	payload := map[string]interface{}{
		"filepath": filepath,
		"mimetype": mimetype,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostSubredditEmojiCustomSize makes a POST request to /api/v1/{subreddit}/emoji_custom_size
ID: POST /api/v1/{subreddit}/emoji_custom_size
Description: Set custom emoji size.Omitting width or height will disable custom emoji sizing.
*/
func (sdk *ReddiGoSDK) PostSubredditEmojiCustomSize(subreddit string, height int, width int) (any, error) {
	reqUrl := fmt.Sprintf("/api/v1/%s/emoji_custom_size", subreddit)
	payload := map[string]interface{}{
		"height": height,
		"width":  width,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
GetSubredditEmojisAll makes a GET request to /api/v1/{subreddit}/emojis/all
ID: GET /api/v1/{subreddit}/emojis/all
Description: Get all emojis for a SR. The response inclueds snoomojis
as well as emojis for the SR specified in the request.The response has 2 keys:
  - snoomojis
  - SR emojis
*/
func (sdk *ReddiGoSDK) GetSubredditEmojisAll(subreddit string) (any, error) {
	reqUrl := fmt.Sprintf("/api/v1/%s/emojis/all", subreddit)
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

type PostRSubredditClearflairtemplatesFlairTypeEnum string

const (
	PostRSubredditClearflairtemplatesFlairTypeEnumUSER_FLAIR PostRSubredditClearflairtemplatesFlairTypeEnum = "USER_FLAIR"
	PostRSubredditClearflairtemplatesFlairTypeEnumLINK_FLAIR PostRSubredditClearflairtemplatesFlairTypeEnum = "LINK_FLAIR"
)

/*
PostRSubredditClearflairtemplates makes a POST request to /r/{subreddit}/api/clearflairtemplates
ID: POST /r/{subreddit}/api/clearflairtemplates
Description: No description available
*/
func (sdk *ReddiGoSDK) PostRSubredditClearflairtemplates(subreddit string, apiType string, flairType string) (any, error) {
	reqUrl := fmt.Sprintf("/r/%s/api/clearflairtemplates", subreddit)
	payload := map[string]interface{}{
		"api_type":   apiType,
		"flair_type": flairType,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostRSubredditDeleteflair makes a POST request to /r/{subreddit}/api/deleteflair
ID: POST /r/{subreddit}/api/deleteflair
Description: No description available
*/
func (sdk *ReddiGoSDK) PostRSubredditDeleteflair(subreddit string, apiType string, name interface{}) (any, error) {
	reqUrl := fmt.Sprintf("/r/%s/api/deleteflair", subreddit)
	payload := map[string]interface{}{
		"api_type": apiType,
		"name":     name,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostRSubredditDeleteflairtemplate makes a POST request to /r/{subreddit}/api/deleteflairtemplate
ID: POST /r/{subreddit}/api/deleteflairtemplate
Description: No description available
*/
func (sdk *ReddiGoSDK) PostRSubredditDeleteflairtemplate(subreddit string, apiType string, flairTemplateId interface{}) (any, error) {
	reqUrl := fmt.Sprintf("/r/%s/api/deleteflairtemplate", subreddit)
	payload := map[string]interface{}{
		"api_type":          apiType,
		"flair_template_id": flairTemplateId,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostRSubredditFlair makes a POST request to /r/{subreddit}/api/flair
ID: POST /r/{subreddit}/api/flair
Description: No description available
*/
func (sdk *ReddiGoSDK) PostRSubredditFlair(subreddit string, apiType string, cssClass interface{}, link string, name interface{}, text string) (any, error) {
	reqUrl := fmt.Sprintf("/r/%s/api/flair", subreddit)
	payload := map[string]interface{}{
		"api_type":  apiType,
		"css_class": cssClass,
		"link":      link,
		"name":      name,
		"text":      text,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

type PatchRSubredditFlairTemplateOrderFlairTypeEnum string

const (
	PatchRSubredditFlairTemplateOrderFlairTypeEnumUSER_FLAIR PatchRSubredditFlairTemplateOrderFlairTypeEnum = "USER_FLAIR"
	PatchRSubredditFlairTemplateOrderFlairTypeEnumLINK_FLAIR PatchRSubredditFlairTemplateOrderFlairTypeEnum = "LINK_FLAIR"
)

/*
PatchRSubredditFlairTemplateOrder makes a PATCH request to /r/{subreddit}/api/flair_template_order
ID: PATCH /r/{subreddit}/api/flair_template_order
Description: Update the order of flair templates in the specified subreddit.Order should contain every single flair id for that flair type; omitting
any id will result in a loss of data.
*/
func (sdk *ReddiGoSDK) PatchRSubredditFlairTemplateOrder(subreddit string, flairType string) (any, error) {
	reqUrl := fmt.Sprintf("/r/%s/api/flair_template_order", subreddit)
	payload := map[string]interface{}{
		"flair_type": flairType,
		"subreddit":  subreddit,
	}
	// Construct the request for PATCH method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("PATCH", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

type PostRSubredditFlairconfigFlairPositionEnum string

const (
	PostRSubredditFlairconfigFlairPositionEnumLeft  PostRSubredditFlairconfigFlairPositionEnum = "left"
	PostRSubredditFlairconfigFlairPositionEnumRight PostRSubredditFlairconfigFlairPositionEnum = "right"
)

type PostRSubredditFlairconfigLinkFlairPositionEnum string

const (
	PostRSubredditFlairconfigLinkFlairPositionEnumLeft  PostRSubredditFlairconfigLinkFlairPositionEnum = "left"
	PostRSubredditFlairconfigLinkFlairPositionEnumRight PostRSubredditFlairconfigLinkFlairPositionEnum = "right"
)

/*
PostRSubredditFlairconfig makes a POST request to /r/{subreddit}/api/flairconfig
ID: POST /r/{subreddit}/api/flairconfig
Description: No description available
*/
func (sdk *ReddiGoSDK) PostRSubredditFlairconfig(subreddit string, apiType string, flairEnabled bool, flairPosition string, flairSelfAssignEnabled bool, linkFlairPosition string, linkFlairSelfAssignEnabled bool) (any, error) {
	reqUrl := fmt.Sprintf("/r/%s/api/flairconfig", subreddit)
	payload := map[string]interface{}{
		"api_type":                       apiType,
		"flair_enabled":                  flairEnabled,
		"flair_position":                 flairPosition,
		"flair_self_assign_enabled":      flairSelfAssignEnabled,
		"link_flair_position":            linkFlairPosition,
		"link_flair_self_assign_enabled": linkFlairSelfAssignEnabled,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostRSubredditFlaircsv makes a POST request to /r/{subreddit}/api/flaircsv
ID: POST /r/{subreddit}/api/flaircsv
Description: Change the flair of multiple users in the same subreddit with a
single API call.Requires a string 'flair_csv' which has up to 100 lines of the form
'user,flairtext,cssclass' (Lines beyond the 100th are ignored).If both cssclass and flairtext are the empty string for a given
user, instead clears that user's flair.Returns an array of objects indicating if each flair setting was
applied, or a reason for the failure.
*/
func (sdk *ReddiGoSDK) PostRSubredditFlaircsv(subreddit string, flairCsv interface{}) (any, error) {
	reqUrl := fmt.Sprintf("/r/%s/api/flaircsv", subreddit)
	payload := map[string]interface{}{
		"flair_csv": flairCsv,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

// GetRSubredditFlairlistResponse represents the response for GET /r/{subreddit}/api/flairlist
type GetRSubredditFlairlistResponse struct {
	After    string      `json:"after"`     // fullname of a thing
	Before   string      `json:"before"`    // fullname of a thing
	Count    int         `json:"count"`     // a positive integer (default: 0)
	Limit    interface{} `json:"limit"`     // the maximum number of items desired (default: 25, maximum: 1000)
	Name     interface{} `json:"name"`      // a user by name
	Show     string      `json:"show"`      // (optional) the string all
	SrDetail bool        `json:"sr_detail"` // (optional) expand subreddits
}

/*
GetRSubredditFlairlist makes a GET request to /r/{subreddit}/api/flairlist
ID: GET /r/{subreddit}/api/flairlist
Description: This endpoint is a listing.
*/
func (sdk *ReddiGoSDK) GetRSubredditFlairlist(subreddit string, after string, before string, count string, limit string) (GetRSubredditFlairlistResponse, error) {
	reqUrl := fmt.Sprintf("/r/%s/api/flairlist", subreddit)
	queryParams := urlpkg.Values{}
	queryParams.Add("after", after)
	queryParams.Add("before", before)
	queryParams.Add("count", count)
	queryParams.Add("limit", limit)
	reqUrl += "?" + queryParams.Encode()
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return GetRSubredditFlairlistResponse{}, err
	}
	defer resp.Body.Close()
	var response GetRSubredditFlairlistResponse
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return GetRSubredditFlairlistResponse{}, err
	}
	return response, nil
}

/*
PostRSubredditFlairselector makes a POST request to /r/{subreddit}/api/flairselector
ID: POST /r/{subreddit}/api/flairselector
Description: Return information about a users's flair options.If link is given, return link flair options for an existing link.
If is_newlink is True, return link flairs options for a new link submission.
Otherwise, return user flair options for this subreddit.The logged in user's flair is also returned.
Subreddit moderators may give a user by name to instead
retrieve that user's flair.
*/
func (sdk *ReddiGoSDK) PostRSubredditFlairselector(subreddit string, isNewlink bool, link string, name interface{}) (any, error) {
	reqUrl := fmt.Sprintf("/r/%s/api/flairselector", subreddit)
	payload := map[string]interface{}{
		"is_newlink": isNewlink,
		"link":       link,
		"name":       name,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

type PostRSubredditFlairtemplateFlairTypeEnum string

const (
	PostRSubredditFlairtemplateFlairTypeEnumUSER_FLAIR PostRSubredditFlairtemplateFlairTypeEnum = "USER_FLAIR"
	PostRSubredditFlairtemplateFlairTypeEnumLINK_FLAIR PostRSubredditFlairtemplateFlairTypeEnum = "LINK_FLAIR"
)

/*
PostRSubredditFlairtemplate makes a POST request to /r/{subreddit}/api/flairtemplate
ID: POST /r/{subreddit}/api/flairtemplate
Description: No description available
*/
func (sdk *ReddiGoSDK) PostRSubredditFlairtemplate(subreddit string, apiType string, cssClass interface{}, flairTemplateId interface{}, flairType string, text string, textEditable bool) (any, error) {
	reqUrl := fmt.Sprintf("/r/%s/api/flairtemplate", subreddit)
	payload := map[string]interface{}{
		"api_type":          apiType,
		"css_class":         cssClass,
		"flair_template_id": flairTemplateId,
		"flair_type":        flairType,
		"text":              text,
		"text_editable":     textEditable,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

type PostRSubredditFlairtemplateV2AllowableContentEnum string

const (
	PostRSubredditFlairtemplateV2AllowableContentEnumAll   PostRSubredditFlairtemplateV2AllowableContentEnum = "all"
	PostRSubredditFlairtemplateV2AllowableContentEnumEmoji PostRSubredditFlairtemplateV2AllowableContentEnum = "emoji"
	PostRSubredditFlairtemplateV2AllowableContentEnumText  PostRSubredditFlairtemplateV2AllowableContentEnum = "text"
)

type PostRSubredditFlairtemplateV2FlairTypeEnum string

const (
	PostRSubredditFlairtemplateV2FlairTypeEnumUSER_FLAIR PostRSubredditFlairtemplateV2FlairTypeEnum = "USER_FLAIR"
	PostRSubredditFlairtemplateV2FlairTypeEnumLINK_FLAIR PostRSubredditFlairtemplateV2FlairTypeEnum = "LINK_FLAIR"
)

type PostRSubredditFlairtemplateV2TextColorEnum string

const (
	PostRSubredditFlairtemplateV2TextColorEnumLight PostRSubredditFlairtemplateV2TextColorEnum = "light"
	PostRSubredditFlairtemplateV2TextColorEnumDark  PostRSubredditFlairtemplateV2TextColorEnum = "dark"
)

/*
PostRSubredditFlairtemplateV2 makes a POST request to /r/{subreddit}/api/flairtemplate_v2
ID: POST /r/{subreddit}/api/flairtemplate_v2
Description: Create or update a flair template.This new endpoint is primarily used for the redesign.
*/
func (sdk *ReddiGoSDK) PostRSubredditFlairtemplateV2(subreddit string, allowableContent string, apiType string, backgroundColor interface{}, cssClass interface{}, flairTemplateId interface{}, flairType string, maxEmojis int, modOnly bool, overrideCss interface{}, text string, textColor string, textEditable bool) (any, error) {
	reqUrl := fmt.Sprintf("/r/%s/api/flairtemplate_v2", subreddit)
	payload := map[string]interface{}{
		"allowable_content": allowableContent,
		"api_type":          apiType,
		"background_color":  backgroundColor,
		"css_class":         cssClass,
		"flair_template_id": flairTemplateId,
		"flair_type":        flairType,
		"max_emojis":        maxEmojis,
		"mod_only":          modOnly,
		"override_css":      overrideCss,
		"text":              text,
		"text_color":        textColor,
		"text_editable":     textEditable,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
GetRSubredditLinkFlair makes a GET request to /r/{subreddit}/api/link_flair
ID: GET /r/{subreddit}/api/link_flair
Description: Return list of available link flair for the current subreddit.Will not return flair if the user cannot set their own link flair and
they are not a moderator that can set flair.
*/
func (sdk *ReddiGoSDK) GetRSubredditLinkFlair(subreddit string) (any, error) {
	reqUrl := fmt.Sprintf("/r/%s/api/link_flair", subreddit)
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
GetRSubredditLinkFlairV2 makes a GET request to /r/{subreddit}/api/link_flair_v2
ID: GET /r/{subreddit}/api/link_flair_v2
Description: Return list of available link flair for the current subreddit.Will not return flair if the user cannot set their own link flair and
they are not a moderator that can set flair.
*/
func (sdk *ReddiGoSDK) GetRSubredditLinkFlairV2(subreddit string) (any, error) {
	reqUrl := fmt.Sprintf("/r/%s/api/link_flair_v2", subreddit)
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

type PostRSubredditSelectflairTextColorEnum string

const (
	PostRSubredditSelectflairTextColorEnumLight PostRSubredditSelectflairTextColorEnum = "light"
	PostRSubredditSelectflairTextColorEnumDark  PostRSubredditSelectflairTextColorEnum = "dark"
)

/*
PostRSubredditSelectflair makes a POST request to /r/{subreddit}/api/selectflair
ID: POST /r/{subreddit}/api/selectflair
Description: No description available
*/
func (sdk *ReddiGoSDK) PostRSubredditSelectflair(subreddit string, apiType string, backgroundColor interface{}, cssClass interface{}, flairTemplateId interface{}, link string, name interface{}, returnRtson interface{}, text string, textColor string) (any, error) {
	reqUrl := fmt.Sprintf("/r/%s/api/selectflair", subreddit)
	payload := map[string]interface{}{
		"api_type":          apiType,
		"background_color":  backgroundColor,
		"css_class":         cssClass,
		"flair_template_id": flairTemplateId,
		"link":              link,
		"name":              name,
		"return_rtson":      returnRtson,
		"text":              text,
		"text_color":        textColor,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostRSubredditSetflairenabled makes a POST request to /r/{subreddit}/api/setflairenabled
ID: POST /r/{subreddit}/api/setflairenabled
Description: No description available
*/
func (sdk *ReddiGoSDK) PostRSubredditSetflairenabled(subreddit string, apiType string, flairEnabled bool) (any, error) {
	reqUrl := fmt.Sprintf("/r/%s/api/setflairenabled", subreddit)
	payload := map[string]interface{}{
		"api_type":      apiType,
		"flair_enabled": flairEnabled,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
GetRSubredditUserFlair makes a GET request to /r/{subreddit}/api/user_flair
ID: GET /r/{subreddit}/api/user_flair
Description: Return list of available user flair for the current subreddit.Will not return flair if flair is disabled on the subreddit,
the user cannot set their own flair, or they are not a moderator
that can set flair.
*/
func (sdk *ReddiGoSDK) GetRSubredditUserFlair(subreddit string) (any, error) {
	reqUrl := fmt.Sprintf("/r/%s/api/user_flair", subreddit)
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
GetRSubredditUserFlairV2 makes a GET request to /r/{subreddit}/api/user_flair_v2
ID: GET /r/{subreddit}/api/user_flair_v2
Description: Return list of available user flair for the current subreddit.If user is not a mod of the subreddit, this endpoint filters
out mod_only templates.
*/
func (sdk *ReddiGoSDK) GetRSubredditUserFlairV2(subreddit string) (any, error) {
	reqUrl := fmt.Sprintf("/r/%s/api/user_flair_v2", subreddit)
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostComment makes a POST request to /api/comment
ID: POST /api/comment
Description: Submit a new comment or reply to a message.parent is the fullname of the thing being replied to. Its value
changes the kind of object created by this request:text should be the raw markdown body of the comment or message.To start a new message thread, use /api/compose.
*/
func (sdk *ReddiGoSDK) PostComment(apiType string, recaptchaToken string, returnRtjson bool, richtextJson interface{}, text interface{}, thingId string) (any, error) {
	reqUrl := "/api/comment"
	payload := map[string]interface{}{
		"api_type":        apiType,
		"recaptcha_token": recaptchaToken,
		"return_rtjson":   returnRtjson,
		"richtext_json":   richtextJson,
		"text":            text,
		"thing_id":        thingId,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostDel makes a POST request to /api/del
ID: POST /api/del
Description: Delete a Link or Comment.
*/
func (sdk *ReddiGoSDK) PostDel(id string) (any, error) {
	reqUrl := "/api/del"
	payload := map[string]interface{}{
		"id": id,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostEditusertext makes a POST request to /api/editusertext
ID: POST /api/editusertext
Description: Edit the body text of a comment or self-post.
*/
func (sdk *ReddiGoSDK) PostEditusertext(apiType string, returnRtjson bool, richtextJson interface{}, text interface{}, thingId string) (any, error) {
	reqUrl := "/api/editusertext"
	payload := map[string]interface{}{
		"api_type":      apiType,
		"return_rtjson": returnRtjson,
		"richtext_json": richtextJson,
		"text":          text,
		"thing_id":      thingId,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostFollowPost makes a POST request to /api/follow_post
ID: POST /api/follow_post
Description: Follow or unfollow a post.To follow, follow should be True. To unfollow, follow should
be False. The user must have access to the subreddit to be able to
follow a post within it.
*/
func (sdk *ReddiGoSDK) PostFollowPost(follow bool, fullname string) (any, error) {
	reqUrl := "/api/follow_post"
	payload := map[string]interface{}{
		"follow":   follow,
		"fullname": fullname,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostHide makes a POST request to /api/hide
ID: POST /api/hide
Description: Hide a link.This removes it from the user's default view of subreddit listings.See also: /api/unhide.
*/
func (sdk *ReddiGoSDK) PostHide(id string) (any, error) {
	reqUrl := "/api/hide"
	payload := map[string]interface{}{
		"id": id,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

// GetRSubredditInfoResponse represents the response for GET /r/{subreddit}/api/info
type GetRSubredditInfoResponse struct {
	Id     string      `json:"id"`      // A comma-separated list of thing fullnames
	SrName interface{} `json:"sr_name"` // comma-delimited list of subreddit names
	Url    string      `json:"url"`     // a valid URL
}

/*
GetRSubredditInfo makes a GET request to /r/{subreddit}/api/info
ID: GET /r/{subreddit}/api/info
Description: Return a listing of things specified by their fullnames.Only Links, Comments, and Subreddits are allowed.
*/
func (sdk *ReddiGoSDK) GetRSubredditInfo(subreddit string) (GetRSubredditInfoResponse, error) {
	reqUrl := fmt.Sprintf("/r/%s/api/info", subreddit)
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return GetRSubredditInfoResponse{}, err
	}
	defer resp.Body.Close()
	var response GetRSubredditInfoResponse
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return GetRSubredditInfoResponse{}, err
	}
	return response, nil
}

/*
PostLock makes a POST request to /api/lock
ID: POST /api/lock
Description: Lock a link or comment.Prevents a post or new child comments from receiving new comments.See also: /api/unlock.
*/
func (sdk *ReddiGoSDK) PostLock(id string) (any, error) {
	reqUrl := "/api/lock"
	payload := map[string]interface{}{
		"id": id,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostMarknsfw makes a POST request to /api/marknsfw
ID: POST /api/marknsfw
Description: Mark a link NSFW.See also: /api/unmarknsfw.
*/
func (sdk *ReddiGoSDK) PostMarknsfw(id string) (any, error) {
	reqUrl := "/api/marknsfw"
	payload := map[string]interface{}{
		"id": id,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

type GetMorechildrenSortEnum string

const (
	GetMorechildrenSortEnumConfidence    GetMorechildrenSortEnum = "confidence"
	GetMorechildrenSortEnumTop           GetMorechildrenSortEnum = "top"
	GetMorechildrenSortEnumNew           GetMorechildrenSortEnum = "new"
	GetMorechildrenSortEnumControversial GetMorechildrenSortEnum = "controversial"
	GetMorechildrenSortEnumOld           GetMorechildrenSortEnum = "old"
	GetMorechildrenSortEnumRandom        GetMorechildrenSortEnum = "random"
	GetMorechildrenSortEnumQa            GetMorechildrenSortEnum = "qa"
	GetMorechildrenSortEnumLive          GetMorechildrenSortEnum = "live"
)

// GetMorechildrenResponse represents the response for GET /api/morechildren
type GetMorechildrenResponse struct {
	ApiType       string      `json:"api_type"`       // the string json
	Children      interface{} `json:"children"`       //
	Depth         int         `json:"depth"`          // (optional) an integer
	Id            interface{} `json:"id"`             // (optional) id of the associated MoreChildren object
	LimitChildren bool        `json:"limit_children"` // boolean value
	LinkId        string      `json:"link_id"`        // fullname of a link
	Sort          string      `json:"sort"`           // one of (confidence, top, new, controversial, old, random, qa, live)
}

/*
GetMorechildren makes a GET request to /api/morechildren
ID: GET /api/morechildren
Description: Retrieve additional comments omitted from a base comment tree.When a comment tree is rendered, the most relevant comments are
selected for display first. Remaining comments are stubbed out with
"MoreComments" links. This API call is used to retrieve the additional
comments represented by those stubs, up to 100 at a time.The two core parameters required are link and children.  link is
the fullname of the link whose comments are being fetched. children
is a comma-delimited list of comment ID36s that need to be fetched.If id is passed, it should be the ID of the MoreComments object this
call is replacing. This is needed only for the HTML UI's purposes and
is optional otherwise.NOTE: you may only make one request at a time to this API endpoint.
Higher concurrency will result in an error being returned.If limit_children is True, only return the children requested.depth is the maximum depth of subtrees in the thread.
*/
func (sdk *ReddiGoSDK) GetMorechildren() (GetMorechildrenResponse, error) {
	reqUrl := "/api/morechildren"
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return GetMorechildrenResponse{}, err
	}
	defer resp.Body.Close()
	var response GetMorechildrenResponse
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return GetMorechildrenResponse{}, err
	}
	return response, nil
}

/*
PostReport makes a POST request to /api/report
ID: POST /api/report
Description: Report a link, comment or message.
Reporting a thing brings it to the attention of the subreddit's
moderators. Reporting a message sends it to a system for admin review.
For links and comments, the thing is implicitly hidden as well (see
/api/hide for details).See /r/{subreddit}/about/rules for
for more about subreddit rules, and /r/{subreddit}/about
for more about free_form_reports.
*/
func (sdk *ReddiGoSDK) PostReport(additionalInfo string, apiType string, customText string, fromHelpDesk bool, fromModmail bool, modmailConvId interface{}, otherReason string, reason string, ruleReason string, siteReason string, srName string, thingId string, usernames string) (any, error) {
	reqUrl := "/api/report"
	payload := map[string]interface{}{
		"additional_info": additionalInfo,
		"api_type":        apiType,
		"custom_text":     customText,
		"from_help_desk":  fromHelpDesk,
		"from_modmail":    fromModmail,
		"modmail_conv_id": modmailConvId,
		"other_reason":    otherReason,
		"reason":          reason,
		"rule_reason":     ruleReason,
		"site_reason":     siteReason,
		"sr_name":         srName,
		"thing_id":        thingId,
		"usernames":       usernames,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostReportAward makes a POST request to /api/report_award
ID: POST /api/report_award
Description: No description available
*/
func (sdk *ReddiGoSDK) PostReportAward(awardId string, reason string) (any, error) {
	reqUrl := "/api/report_award"
	payload := map[string]interface{}{
		"award_id": awardId,
		"reason":   reason,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostSave makes a POST request to /api/save
ID: POST /api/save
Description: Save a link or comment.Saved things are kept in the user's saved listing for later perusal.See also: /api/unsave.
*/
func (sdk *ReddiGoSDK) PostSave(category interface{}, id string) (any, error) {
	reqUrl := "/api/save"
	payload := map[string]interface{}{
		"category": category,
		"id":       id,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
GetSavedCategories makes a GET request to /api/saved_categories
ID: GET /api/saved_categories
Description: Get a list of categories in which things are currently saved.See also: /api/save.
*/
func (sdk *ReddiGoSDK) GetSavedCategories() (any, error) {
	reqUrl := "/api/saved_categories"
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostSendreplies makes a POST request to /api/sendreplies
ID: POST /api/sendreplies
Description: Enable or disable inbox replies for a link or comment.state is a boolean that indicates whether you are enabling or
disabling inbox replies - true to enable, false to disable.
*/
func (sdk *ReddiGoSDK) PostSendreplies(id string, state bool) (any, error) {
	reqUrl := "/api/sendreplies"
	payload := map[string]interface{}{
		"id":    id,
		"state": state,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostSetContestMode makes a POST request to /api/set_contest_mode
ID: POST /api/set_contest_mode
Description: Set or unset "contest mode" for a link's comments.state is a boolean that indicates whether you are enabling or
disabling contest mode - true to enable, false to disable.
*/
func (sdk *ReddiGoSDK) PostSetContestMode(apiType string, id interface{}, state bool) (any, error) {
	reqUrl := "/api/set_contest_mode"
	payload := map[string]interface{}{
		"api_type": apiType,
		"id":       id,
		"state":    state,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

type GetRSubredditAboutLocationOnlyEnum string

const (
	GetRSubredditAboutLocationOnlyEnumLinks         GetRSubredditAboutLocationOnlyEnum = "links"
	GetRSubredditAboutLocationOnlyEnumComments      GetRSubredditAboutLocationOnlyEnum = "comments"
	GetRSubredditAboutLocationOnlyEnumChat_comments GetRSubredditAboutLocationOnlyEnum = "chat_comments"
)

// GetRSubredditAboutLocationResponse represents the response for GET /r/{subreddit}/about/{location}
type GetRSubredditAboutLocationResponse struct {
	After    string      `json:"after"`     // fullname of a thing
	Before   string      `json:"before"`    // fullname of a thing
	Count    int         `json:"count"`     // a positive integer (default: 0)
	Limit    interface{} `json:"limit"`     // the maximum number of items desired (default: 25, maximum: 100)
	Location interface{} `json:"location"`  //
	Only     string      `json:"only"`      // one of (links, comments, chat_comments)
	Show     string      `json:"show"`      // (optional) the string all
	SrDetail bool        `json:"sr_detail"` // (optional) expand subreddits
}

/*
GetRSubredditAboutLocation makes a GET request to /r/{subreddit}/about/{location}
ID: GET /r/{subreddit}/about/{location}
Description: Return a listing of posts relevant to moderators.Requires the "posts" moderator permission for the subreddit.This endpoint is a listing.
*/
func (sdk *ReddiGoSDK) GetRSubredditAboutLocation(subreddit string, location string, after string, before string, count string, limit string) (GetRSubredditAboutLocationResponse, error) {
	reqUrl := fmt.Sprintf("/r/%s/about/%s", subreddit, location)
	queryParams := urlpkg.Values{}
	queryParams.Add("after", after)
	queryParams.Add("before", before)
	queryParams.Add("count", count)
	queryParams.Add("limit", limit)
	reqUrl += "?" + queryParams.Encode()
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return GetRSubredditAboutLocationResponse{}, err
	}
	defer resp.Body.Close()
	var response GetRSubredditAboutLocationResponse
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return GetRSubredditAboutLocationResponse{}, err
	}
	return response, nil
}

/*
PostRSubredditAcceptModeratorInvite makes a POST request to /r/{subreddit}/api/accept_moderator_invite
ID: POST /r/{subreddit}/api/accept_moderator_invite
Description: Accept an invite to moderate the specified subreddit.The authenticated user must have been invited to moderate the subreddit
by one of its current moderators.See also: /api/friend and
/subreddits/mine.
*/
func (sdk *ReddiGoSDK) PostRSubredditAcceptModeratorInvite(subreddit string, apiType string) (any, error) {
	reqUrl := fmt.Sprintf("/r/%s/api/accept_moderator_invite", subreddit)
	payload := map[string]interface{}{
		"api_type": apiType,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostApprove makes a POST request to /api/approve
ID: POST /api/approve
Description: Approve a link or comment.If the thing was removed, it will be re-inserted into appropriate
listings. Any reports on the approved thing will be discarded.See also: /api/remove.
*/
func (sdk *ReddiGoSDK) PostApprove(id string) (any, error) {
	reqUrl := "/api/approve"
	payload := map[string]interface{}{
		"id": id,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

type PostDistinguishHowEnum string

const (
	PostDistinguishHowEnumYes     PostDistinguishHowEnum = "yes"
	PostDistinguishHowEnumNo      PostDistinguishHowEnum = "no"
	PostDistinguishHowEnumAdmin   PostDistinguishHowEnum = "admin"
	PostDistinguishHowEnumSpecial PostDistinguishHowEnum = "special"
)

/*
PostDistinguish makes a POST request to /api/distinguish
ID: POST /api/distinguish
Description: Distinguish a thing's author with a sigil.This can be useful to draw attention to and confirm the identity of the
user in the context of a link or comment of theirs. The options for
distinguish are as follows:The first time a top-level comment is moderator distinguished, the
author of the link the comment is in reply to will get a notification
in their inbox.sticky is a boolean flag for comments, which will stick the
distingushed comment to the top of all comments threads. If a comment
is marked sticky, it will override any other stickied comment for that
link (as only one comment may be stickied at a time.) Only top-level
comments may be stickied.
*/
func (sdk *ReddiGoSDK) PostDistinguish(apiType string, how string, id string, sticky bool) (any, error) {
	reqUrl := "/api/distinguish"
	payload := map[string]interface{}{
		"api_type": apiType,
		"how":      how,
		"id":       id,
		"sticky":   sticky,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostIgnoreReports makes a POST request to /api/ignore_reports
ID: POST /api/ignore_reports
Description: Prevent future reports on a thing from causing notifications.Any reports made about a thing after this flag is set on it will not
cause notifications or make the thing show up in the various moderation
listings.See also: /api/unignore_reports.
*/
func (sdk *ReddiGoSDK) PostIgnoreReports(id string) (any, error) {
	reqUrl := "/api/ignore_reports"
	payload := map[string]interface{}{
		"id": id,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostLeavecontributor makes a POST request to /api/leavecontributor
ID: POST /api/leavecontributor
Description: Abdicate approved user status in a subreddit.See also: /api/friend.
*/
func (sdk *ReddiGoSDK) PostLeavecontributor(id string) (any, error) {
	reqUrl := "/api/leavecontributor"
	payload := map[string]interface{}{
		"id": id,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostLeavemoderator makes a POST request to /api/leavemoderator
ID: POST /api/leavemoderator
Description: Abdicate moderator status in a subreddit.See also: /api/friend.
*/
func (sdk *ReddiGoSDK) PostLeavemoderator(id string) (any, error) {
	reqUrl := "/api/leavemoderator"
	payload := map[string]interface{}{
		"id": id,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostMuteMessageAuthor makes a POST request to /api/mute_message_author
ID: POST /api/mute_message_author
Description: For muting user via modmail.
*/
func (sdk *ReddiGoSDK) PostMuteMessageAuthor(id string) (any, error) {
	reqUrl := "/api/mute_message_author"
	payload := map[string]interface{}{
		"id": id,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostRemove makes a POST request to /api/remove
ID: POST /api/remove
Description: Remove a link, comment, or modmail message.If the thing is a link, it will be removed from all subreddit listings.
If the thing is a comment, it will be redacted and removed from all
subreddit comment listings.See also: /api/approve.
*/
func (sdk *ReddiGoSDK) PostRemove(id string, spam bool) (any, error) {
	reqUrl := "/api/remove"
	payload := map[string]interface{}{
		"id":   id,
		"spam": spam,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostShowComment makes a POST request to /api/show_comment
ID: POST /api/show_comment
Description: Mark a comment that it should not be collapsed because of crowd control.The comment could still be collapsed for other reasons.
*/
func (sdk *ReddiGoSDK) PostShowComment(id string) (any, error) {
	reqUrl := "/api/show_comment"
	payload := map[string]interface{}{
		"id": id,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostSnoozeReports makes a POST request to /api/snooze_reports
ID: POST /api/snooze_reports
Description: Prevent future reports on a thing from causing notifications.For users who reported this thing (post, comment, etc) with
the given report reason, reports from those users in the
next 7 days will not be escalated to moderators.
See also: /api/unsnooze_reports.
*/
func (sdk *ReddiGoSDK) PostSnoozeReports(id string, reason interface{}) (any, error) {
	reqUrl := "/api/snooze_reports"
	payload := map[string]interface{}{
		"id":     id,
		"reason": reason,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostUnignoreReports makes a POST request to /api/unignore_reports
ID: POST /api/unignore_reports
Description: Allow future reports on a thing to cause notifications.See also: /api/ignore_reports.
*/
func (sdk *ReddiGoSDK) PostUnignoreReports(id string) (any, error) {
	reqUrl := "/api/unignore_reports"
	payload := map[string]interface{}{
		"id": id,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostUnmuteMessageAuthor makes a POST request to /api/unmute_message_author
ID: POST /api/unmute_message_author
Description: For unmuting user via modmail.
*/
func (sdk *ReddiGoSDK) PostUnmuteMessageAuthor(id string) (any, error) {
	reqUrl := "/api/unmute_message_author"
	payload := map[string]interface{}{
		"id": id,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostUnsnoozeReports makes a POST request to /api/unsnooze_reports
ID: POST /api/unsnooze_reports
Description: For users whose reports were snoozed
(see /api/snooze_reports),
to go back to escalating future reports from those users.
*/
func (sdk *ReddiGoSDK) PostUnsnoozeReports(id string, reason interface{}) (any, error) {
	reqUrl := "/api/unsnooze_reports"
	payload := map[string]interface{}{
		"id":     id,
		"reason": reason,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostUpdateCrowdControlLevel makes a POST request to /api/update_crowd_control_level
ID: POST /api/update_crowd_control_level
Description: Change the post's crowd control level.
*/
func (sdk *ReddiGoSDK) PostUpdateCrowdControlLevel(id string, level int) (any, error) {
	reqUrl := "/api/update_crowd_control_level"
	payload := map[string]interface{}{
		"id":    id,
		"level": level,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
GetRSubredditStylesheet makes a GET request to /r/{subreddit}/stylesheet
ID: GET /r/{subreddit}/stylesheet
Description: Redirect to the subreddit's stylesheet if one exists.See also: /api/subreddit_stylesheet.
*/
func (sdk *ReddiGoSDK) GetRSubredditStylesheet(subreddit string) (any, error) {
	reqUrl := fmt.Sprintf("/r/%s/stylesheet", subreddit)
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

type PostModBulkReadStateEnum string

const (
	PostModBulkReadStateEnumAll           PostModBulkReadStateEnum = "all"
	PostModBulkReadStateEnumAppeals       PostModBulkReadStateEnum = "appeals"
	PostModBulkReadStateEnumNotifications PostModBulkReadStateEnum = "notifications"
	PostModBulkReadStateEnumInbox         PostModBulkReadStateEnum = "inbox"
	PostModBulkReadStateEnumFiltered      PostModBulkReadStateEnum = "filtered"
	PostModBulkReadStateEnumInprogress    PostModBulkReadStateEnum = "inprogress"
	PostModBulkReadStateEnumMod           PostModBulkReadStateEnum = "mod"
	PostModBulkReadStateEnumArchived      PostModBulkReadStateEnum = "archived"
	PostModBulkReadStateEnumDefault       PostModBulkReadStateEnum = "default"
	PostModBulkReadStateEnumHighlighted   PostModBulkReadStateEnum = "highlighted"
	PostModBulkReadStateEnumJoin_requests PostModBulkReadStateEnum = "join_requests"
	PostModBulkReadStateEnumNew           PostModBulkReadStateEnum = "new"
)

/*
PostModBulkRead makes a POST request to /api/mod/bulk_read
ID: POST /api/mod/bulk_read
Description: Marks all conversations read for a particular conversation state
within the passed list of subreddits.
*/
func (sdk *ReddiGoSDK) PostModBulkRead(entity interface{}, state string) (any, error) {
	reqUrl := "/api/mod/bulk_read"
	payload := map[string]interface{}{
		"entity": entity,
		"state":  state,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

type GetModConversationsSortEnum string

const (
	GetModConversationsSortEnumRecent GetModConversationsSortEnum = "recent"
	GetModConversationsSortEnumMod    GetModConversationsSortEnum = "mod"
	GetModConversationsSortEnumUser   GetModConversationsSortEnum = "user"
	GetModConversationsSortEnumUnread GetModConversationsSortEnum = "unread"
)

type GetModConversationsStateEnum string

const (
	GetModConversationsStateEnumAll           GetModConversationsStateEnum = "all"
	GetModConversationsStateEnumAppeals       GetModConversationsStateEnum = "appeals"
	GetModConversationsStateEnumNotifications GetModConversationsStateEnum = "notifications"
	GetModConversationsStateEnumInbox         GetModConversationsStateEnum = "inbox"
	GetModConversationsStateEnumFiltered      GetModConversationsStateEnum = "filtered"
	GetModConversationsStateEnumInprogress    GetModConversationsStateEnum = "inprogress"
	GetModConversationsStateEnumMod           GetModConversationsStateEnum = "mod"
	GetModConversationsStateEnumArchived      GetModConversationsStateEnum = "archived"
	GetModConversationsStateEnumDefault       GetModConversationsStateEnum = "default"
	GetModConversationsStateEnumHighlighted   GetModConversationsStateEnum = "highlighted"
	GetModConversationsStateEnumJoin_requests GetModConversationsStateEnum = "join_requests"
	GetModConversationsStateEnumNew           GetModConversationsStateEnum = "new"
)

// GetModConversationsResponse represents the response for GET /api/mod/conversations
type GetModConversationsResponse struct {
	After  interface{} `json:"after"`  // A Modmail Conversation ID, in the form ModmailConversation_<id>
	Entity interface{} `json:"entity"` // comma-delimited list of subreddit names
	Limit  int         `json:"limit"`  // an integer between 1 and 100 (default: 25)
	Sort   string      `json:"sort"`   // one of (recent, mod, user, unread)
	State  string      `json:"state"`  // one of (all, appeals, notifications, inbox, filtered, inprogress, mod, archived, default, highlighted, join_requests, new)
}

/*
GetModConversations makes a GET request to /api/mod/conversations
ID: GET /api/mod/conversations
Description: Get conversations for a logged in user or subreddits
*/
func (sdk *ReddiGoSDK) GetModConversations(after string, limit string) (GetModConversationsResponse, error) {
	reqUrl := "/api/mod/conversations"
	queryParams := urlpkg.Values{}
	queryParams.Add("after", after)
	queryParams.Add("limit", limit)
	reqUrl += "?" + queryParams.Encode()
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return GetModConversationsResponse{}, err
	}
	defer resp.Body.Close()
	var response GetModConversationsResponse
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return GetModConversationsResponse{}, err
	}
	return response, nil
}

/*
PostModConversations makes a POST request to /api/mod/conversations
ID: POST /api/mod/conversations
Description: Creates a new conversation for a particular SR.This endpoint will create a ModmailConversation object as
well as the first ModmailMessage within the ModmailConversation
object.A note on to:The to field for this endpoint is somewhat confusing. It can be:In this way to is a bit of a misnomer in modmail conversations. What
it really means is the participant of the conversation who is not a mod
of the subreddit.
*/
func (sdk *ReddiGoSDK) PostModConversations(body interface{}, isAuthorHidden bool, srName interface{}, subject string, to string) (any, error) {
	reqUrl := "/api/mod/conversations"
	payload := map[string]interface{}{
		"body":           body,
		"isauthorhidden": isAuthorHidden,
		"srname":         srName,
		"subject":        subject,
		"to":             to,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

// GetModConversationsConversationIdResponse represents the response for GET /api/mod/conversations/{conversation_id}
type GetModConversationsConversationIdResponse struct {
	ConversationId interface{} `json:"conversation_id"` // A Modmail Conversation ID, in the form ModmailConversation_<id>
	MarkRead       bool        `json:"markread"`        // boolean value
}

/*
GetModConversationsConversationId makes a GET request to /api/mod/conversations/{conversation_id}
ID: GET /api/mod/conversations/{conversation_id}
Description: Returns all messages, mod actions and conversation metadata
for a given conversation id
*/
func (sdk *ReddiGoSDK) GetModConversationsConversationId(conversationId string) (GetModConversationsConversationIdResponse, error) {
	reqUrl := fmt.Sprintf("/api/mod/conversations/%s", conversationId)
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return GetModConversationsConversationIdResponse{}, err
	}
	defer resp.Body.Close()
	var response GetModConversationsConversationIdResponse
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return GetModConversationsConversationIdResponse{}, err
	}
	return response, nil
}

/*
PostModConversationsConversationId makes a POST request to /api/mod/conversations/{conversation_id}
ID: POST /api/mod/conversations/{conversation_id}
Description: Creates a new message for a particular conversation.
*/
func (sdk *ReddiGoSDK) PostModConversationsConversationId(conversationId string, body interface{}, isAuthorHidden bool, isInternal bool) (any, error) {
	reqUrl := fmt.Sprintf("/api/mod/conversations/%s", conversationId)
	payload := map[string]interface{}{
		"body":            body,
		"conversation_id": conversationId,
		"isauthorhidden":  isAuthorHidden,
		"isinternal":      isInternal,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostModConversationsConversationIdApprove makes a POST request to /api/mod/conversations/{conversation_id}/approve
ID: POST /api/mod/conversations/{conversation_id}/approve
Description: Approve the non mod user associated with a particular conversation.
*/
func (sdk *ReddiGoSDK) PostModConversationsConversationIdApprove(conversationId string) (any, error) {
	reqUrl := fmt.Sprintf("/api/mod/conversations/%s/approve", conversationId)
	payload := map[string]interface{}{
		"conversation_id": conversationId,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostModConversationsConversationIdArchive makes a POST request to /api/mod/conversations/{conversation_id}/archive
ID: POST /api/mod/conversations/{conversation_id}/archive
Description: Marks a conversation as archived.
*/
func (sdk *ReddiGoSDK) PostModConversationsConversationIdArchive(conversationId string) (any, error) {
	reqUrl := fmt.Sprintf("/api/mod/conversations/%s/archive", conversationId)
	payload := map[string]interface{}{
		"conversation_id": conversationId,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostModConversationsConversationIdDisapprove makes a POST request to /api/mod/conversations/{conversation_id}/disapprove
ID: POST /api/mod/conversations/{conversation_id}/disapprove
Description: Disapprove the non mod user associated with a particular conversation.
*/
func (sdk *ReddiGoSDK) PostModConversationsConversationIdDisapprove(conversationId string) (any, error) {
	reqUrl := fmt.Sprintf("/api/mod/conversations/%s/disapprove", conversationId)
	payload := map[string]interface{}{
		"conversation_id": conversationId,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

// DeleteModConversationsConversationIdHighlightResponse represents the response for DELETE /api/mod/conversations/{conversation_id}/highlight
type DeleteModConversationsConversationIdHighlightResponse struct {
	ConversationId interface{} `json:"conversation_id"` // A Modmail Conversation ID, in the form ModmailConversation_<id>
}

/*
DeleteModConversationsConversationIdHighlight makes a DELETE request to /api/mod/conversations/{conversation_id}/highlight
ID: DELETE /api/mod/conversations/{conversation_id}/highlight
Description: Removes a highlight from a conversation.
*/
func (sdk *ReddiGoSDK) DeleteModConversationsConversationIdHighlight(conversationId string) (DeleteModConversationsConversationIdHighlightResponse, error) {
	reqUrl := fmt.Sprintf("/api/mod/conversations/%s/highlight", conversationId)
	// Construct the request for DELETE method
	resp, err := sdk.MakeRequest("DELETE", reqUrl, nil)
	if err != nil {
		return DeleteModConversationsConversationIdHighlightResponse{}, err
	}
	defer resp.Body.Close()
	var response DeleteModConversationsConversationIdHighlightResponse
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return DeleteModConversationsConversationIdHighlightResponse{}, err
	}
	return response, nil
}

/*
PostModConversationsConversationIdHighlight makes a POST request to /api/mod/conversations/{conversation_id}/highlight
ID: POST /api/mod/conversations/{conversation_id}/highlight
Description: Marks a conversation as highlighted.
*/
func (sdk *ReddiGoSDK) PostModConversationsConversationIdHighlight(conversationId string) (any, error) {
	reqUrl := fmt.Sprintf("/api/mod/conversations/%s/highlight", conversationId)
	payload := map[string]interface{}{
		"conversation_id": conversationId,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

type PostModConversationsConversationIdMuteNumHoursEnum string

const (
	PostModConversationsConversationIdMuteNumHoursEnum72  PostModConversationsConversationIdMuteNumHoursEnum = "72"
	PostModConversationsConversationIdMuteNumHoursEnum168 PostModConversationsConversationIdMuteNumHoursEnum = "168"
	PostModConversationsConversationIdMuteNumHoursEnum672 PostModConversationsConversationIdMuteNumHoursEnum = "672"
)

/*
PostModConversationsConversationIdMute makes a POST request to /api/mod/conversations/{conversation_id}/mute
ID: POST /api/mod/conversations/{conversation_id}/mute
Description: Mutes the non mod user associated with a particular conversation.
*/
func (sdk *ReddiGoSDK) PostModConversationsConversationIdMute(conversationId string, numHours string) (any, error) {
	reqUrl := fmt.Sprintf("/api/mod/conversations/%s/mute", conversationId)
	payload := map[string]interface{}{
		"conversation_id": conversationId,
		"num_hours":       numHours,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostModConversationsConversationIdTempBan makes a POST request to /api/mod/conversations/{conversation_id}/temp_ban
ID: POST /api/mod/conversations/{conversation_id}/temp_ban
Description: Temporary ban (switch from permanent to temporary ban) the non mod
user associated with a particular conversation.
*/
func (sdk *ReddiGoSDK) PostModConversationsConversationIdTempBan(conversationId string, duration int) (any, error) {
	reqUrl := fmt.Sprintf("/api/mod/conversations/%s/temp_ban", conversationId)
	payload := map[string]interface{}{
		"conversation_id": conversationId,
		"duration":        duration,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostModConversationsConversationIdUnarchive makes a POST request to /api/mod/conversations/{conversation_id}/unarchive
ID: POST /api/mod/conversations/{conversation_id}/unarchive
Description: Marks conversation as unarchived.
*/
func (sdk *ReddiGoSDK) PostModConversationsConversationIdUnarchive(conversationId string) (any, error) {
	reqUrl := fmt.Sprintf("/api/mod/conversations/%s/unarchive", conversationId)
	payload := map[string]interface{}{
		"conversation_id": conversationId,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostModConversationsConversationIdUnban makes a POST request to /api/mod/conversations/{conversation_id}/unban
ID: POST /api/mod/conversations/{conversation_id}/unban
Description: Unban the non mod user associated with a particular conversation.
*/
func (sdk *ReddiGoSDK) PostModConversationsConversationIdUnban(conversationId string) (any, error) {
	reqUrl := fmt.Sprintf("/api/mod/conversations/%s/unban", conversationId)
	payload := map[string]interface{}{
		"conversation_id": conversationId,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostModConversationsConversationIdUnmute makes a POST request to /api/mod/conversations/{conversation_id}/unmute
ID: POST /api/mod/conversations/{conversation_id}/unmute
Description: Unmutes the non mod user associated with
a particular conversation.
*/
func (sdk *ReddiGoSDK) PostModConversationsConversationIdUnmute(conversationId string) (any, error) {
	reqUrl := fmt.Sprintf("/api/mod/conversations/%s/unmute", conversationId)
	payload := map[string]interface{}{
		"conversation_id": conversationId,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostModConversationsRead makes a POST request to /api/mod/conversations/read
ID: POST /api/mod/conversations/read
Description: Marks a conversations as read for the user.
*/
func (sdk *ReddiGoSDK) PostModConversationsRead(conversationIds string) (any, error) {
	reqUrl := "/api/mod/conversations/read"
	payload := map[string]interface{}{
		"conversationids": conversationIds,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
GetModConversationsSubreddits makes a GET request to /api/mod/conversations/subreddits
ID: GET /api/mod/conversations/subreddits
Description: Returns a list of srs that the user moderates with mail permission
*/
func (sdk *ReddiGoSDK) GetModConversationsSubreddits() (any, error) {
	reqUrl := "/api/mod/conversations/subreddits"
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostModConversationsUnread makes a POST request to /api/mod/conversations/unread
ID: POST /api/mod/conversations/unread
Description: Marks conversations as unread for the user.
*/
func (sdk *ReddiGoSDK) PostModConversationsUnread(conversationIds string) (any, error) {
	reqUrl := "/api/mod/conversations/unread"
	payload := map[string]interface{}{
		"conversationids": conversationIds,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
GetModConversationsUnreadCount makes a GET request to /api/mod/conversations/unread/count
ID: GET /api/mod/conversations/unread/count
Description: Endpoint to retrieve the unread conversation count by
conversation state.
*/
func (sdk *ReddiGoSDK) GetModConversationsUnreadCount() (any, error) {
	reqUrl := "/api/mod/conversations/unread/count"
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

// DeleteModNotesResponse represents the response for DELETE /api/mod/notes
type DeleteModNotesResponse struct {
	NoteId    interface{} `json:"note_id"`   // a unique ID for the note to be deleted (should have a ModNote_ prefix)
	Subreddit interface{} `json:"subreddit"` // subreddit name
	User      interface{} `json:"user"`      // account username
}

/*
DeleteModNotes makes a DELETE request to /api/mod/notes
ID: DELETE /api/mod/notes
Description: Delete a mod user note where type=NOTE.Parameters should be passed as query parameters.
*/
func (sdk *ReddiGoSDK) DeleteModNotes() (DeleteModNotesResponse, error) {
	reqUrl := "/api/mod/notes"
	// Construct the request for DELETE method
	resp, err := sdk.MakeRequest("DELETE", reqUrl, nil)
	if err != nil {
		return DeleteModNotesResponse{}, err
	}
	defer resp.Body.Close()
	var response DeleteModNotesResponse
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return DeleteModNotesResponse{}, err
	}
	return response, nil
}

// GetModNotesResponse represents the response for GET /api/mod/notes
type GetModNotesResponse struct {
	Before    string      `json:"before"`    // (optional) an encoded string used for pagination with mod notes
	Filter    interface{} `json:"filter"`    // (optional) one of (NOTE, APPROVAL, REMOVAL, BAN, MUTE, INVITE, SPAM, CONTENT_CHANGE, MOD_ACTION, ALL), to be used for querying specific types of mod notes (default: all)
	Limit     interface{} `json:"limit"`     // (optional) the number of mod notes to return in the response payload (default: 25, max: 100)'}
	Subreddit interface{} `json:"subreddit"` // subreddit name
	User      interface{} `json:"user"`      // account username
}

/*
GetModNotes makes a GET request to /api/mod/notes
ID: GET /api/mod/notes
Description: Get mod notes for a specific user in a given subreddit.
*/
func (sdk *ReddiGoSDK) GetModNotes(before string, limit string) (GetModNotesResponse, error) {
	reqUrl := "/api/mod/notes"
	queryParams := urlpkg.Values{}
	queryParams.Add("before", before)
	queryParams.Add("limit", limit)
	reqUrl += "?" + queryParams.Encode()
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return GetModNotesResponse{}, err
	}
	defer resp.Body.Close()
	var response GetModNotesResponse
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return GetModNotesResponse{}, err
	}
	return response, nil
}

/*
PostModNotes makes a POST request to /api/mod/notes
ID: POST /api/mod/notes
Description: Create a mod user note where type=NOTE.
*/
func (sdk *ReddiGoSDK) PostModNotes(label interface{}, note string, redditId string, subreddit interface{}, user interface{}) (any, error) {
	reqUrl := "/api/mod/notes"
	payload := map[string]interface{}{
		"label":     label,
		"note":      note,
		"reddit_id": redditId,
		"subreddit": subreddit,
		"user":      user,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

// GetModNotesRecentResponse represents the response for GET /api/mod/notes/recent
type GetModNotesRecentResponse struct {
	Subreddits interface{} `json:"subreddits"` // a comma delimited list of subreddits by name
	Users      interface{} `json:"users"`      // a comma delimited list of usernames
}

/*
GetModNotesRecent makes a GET request to /api/mod/notes/recent
ID: GET /api/mod/notes/recent
Description: Fetch the most recent notes written by a moderatorBoth parameters should be comma separated lists of equal lengths.
The first subreddit will be paired with the first account to represent
a query for a mod written note for that account in that subreddit and so
forth for all subsequent pairs of subreddits and accounts.
This request accepts up to 500 pairs of subreddit names and usernames.
Parameters should be passed as query parameters.The response will be a list of mod notes in the order that subreddits and accounts
were given. If no note exist for a given subreddit/account pair, then null
will take its place in the list.
*/
func (sdk *ReddiGoSDK) GetModNotesRecent() (GetModNotesRecentResponse, error) {
	reqUrl := "/api/mod/notes/recent"
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return GetModNotesRecentResponse{}, err
	}
	defer resp.Body.Close()
	var response GetModNotesRecentResponse
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return GetModNotesRecentResponse{}, err
	}
	return response, nil
}

/*
PostMultiCopy makes a POST request to /api/multi/copy
ID: POST /api/multi/copy
Description: Copy a multi.Responds with 409 Conflict if the target already exists.A "copied from ..." line will automatically be appended to the
description.
*/
func (sdk *ReddiGoSDK) PostMultiCopy(descriptionMd interface{}, displayName string, expandSrs bool, from interface{}, to interface{}) (any, error) {
	reqUrl := "/api/multi/copy"
	payload := map[string]interface{}{
		"description_md": descriptionMd,
		"display_name":   displayName,
		"expand_srs":     expandSrs,
		"from":           from,
		"to":             to,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

// GetMultiMineResponse represents the response for GET /api/multi/mine
type GetMultiMineResponse struct {
	ExpandSrs bool `json:"expand_srs"` // boolean value
}

/*
GetMultiMine makes a GET request to /api/multi/mine
ID: GET /api/multi/mine
Description: Fetch a list of multis belonging to the current user.
*/
func (sdk *ReddiGoSDK) GetMultiMine() (GetMultiMineResponse, error) {
	reqUrl := "/api/multi/mine"
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return GetMultiMineResponse{}, err
	}
	defer resp.Body.Close()
	var response GetMultiMineResponse
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return GetMultiMineResponse{}, err
	}
	return response, nil
}

// GetMultiUserUsernameResponse represents the response for GET /api/multi/user/{username}
type GetMultiUserUsernameResponse struct {
	ExpandSrs bool        `json:"expand_srs"` // boolean value
	Username  interface{} `json:"username"`   // A valid, existing reddit username
}

/*
GetMultiUserUsername makes a GET request to /api/multi/user/{username}
ID: GET /api/multi/user/{username}
Description: Fetch a list of public multis belonging to username
*/
func (sdk *ReddiGoSDK) GetMultiUserUsername(username string) (GetMultiUserUsernameResponse, error) {
	reqUrl := fmt.Sprintf("/api/multi/user/%s", username)
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return GetMultiUserUsernameResponse{}, err
	}
	defer resp.Body.Close()
	var response GetMultiUserUsernameResponse
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return GetMultiUserUsernameResponse{}, err
	}
	return response, nil
}

// DeleteMultiMultipathResponse represents the response for DELETE /api/multi/{multipath}
type DeleteMultiMultipathResponse struct {
	Multipath interface{} `json:"multipath"`  // multireddit url path
	ExpandSrs bool        `json:"expand_srs"` // boolean value
}

/*
DeleteMultiMultipath makes a DELETE request to /api/multi/{multipath}
ID: DELETE /api/multi/{multipath}
Description: Delete a multi.
*/
func (sdk *ReddiGoSDK) DeleteMultiMultipath(multipath string) (DeleteMultiMultipathResponse, error) {
	reqUrl := fmt.Sprintf("/api/multi/%s", multipath)
	// Construct the request for DELETE method
	resp, err := sdk.MakeRequest("DELETE", reqUrl, nil)
	if err != nil {
		return DeleteMultiMultipathResponse{}, err
	}
	defer resp.Body.Close()
	var response DeleteMultiMultipathResponse
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return DeleteMultiMultipathResponse{}, err
	}
	return response, nil
}

// GetMultiMultipathResponse represents the response for GET /api/multi/{multipath}
type GetMultiMultipathResponse struct {
	ExpandSrs bool        `json:"expand_srs"` // boolean value
	Multipath interface{} `json:"multipath"`  // multireddit url path
}

/*
GetMultiMultipath makes a GET request to /api/multi/{multipath}
ID: GET /api/multi/{multipath}
Description: Fetch a multi's data and subreddit list by name.
*/
func (sdk *ReddiGoSDK) GetMultiMultipath(multipath string) (GetMultiMultipathResponse, error) {
	reqUrl := fmt.Sprintf("/api/multi/%s", multipath)
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return GetMultiMultipathResponse{}, err
	}
	defer resp.Body.Close()
	var response GetMultiMultipathResponse
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return GetMultiMultipathResponse{}, err
	}
	return response, nil
}

/*
PostMultiMultipath makes a POST request to /api/multi/{multipath}
ID: POST /api/multi/{multipath}
Description: Create a multi. Responds with 409 Conflict if it already exists.
*/
func (sdk *ReddiGoSDK) PostMultiMultipath(multipath string, model interface{}, expandSrs bool) (any, error) {
	reqUrl := fmt.Sprintf("/api/multi/%s", multipath)
	payload := map[string]interface{}{
		"model":      model,
		"multipath":  multipath,
		"expand_srs": expandSrs,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PutMultiMultipath makes a PUT request to /api/multi/{multipath}
ID: PUT /api/multi/{multipath}
Description: Create or update a multi.
*/
func (sdk *ReddiGoSDK) PutMultiMultipath(multipath string, expandSrs bool, model interface{}) (any, error) {
	reqUrl := fmt.Sprintf("/api/multi/%s", multipath)
	payload := map[string]interface{}{
		"expand_srs": expandSrs,
		"model":      model,
		"multipath":  multipath,
	}
	// Construct the request for PUT method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("PUT", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

// GetMultiMultipathDescriptionResponse represents the response for GET /api/multi/{multipath}/description
type GetMultiMultipathDescriptionResponse struct {
	Multipath interface{} `json:"multipath"` // multireddit url path
}

/*
GetMultiMultipathDescription makes a GET request to /api/multi/{multipath}/description
ID: GET /api/multi/{multipath}/description
Description: Get a multi's description.
*/
func (sdk *ReddiGoSDK) GetMultiMultipathDescription(multipath string) (GetMultiMultipathDescriptionResponse, error) {
	reqUrl := fmt.Sprintf("/api/multi/%s/description", multipath)
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return GetMultiMultipathDescriptionResponse{}, err
	}
	defer resp.Body.Close()
	var response GetMultiMultipathDescriptionResponse
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return GetMultiMultipathDescriptionResponse{}, err
	}
	return response, nil
}

/*
PutMultiMultipathDescription makes a PUT request to /api/multi/{multipath}/description
ID: PUT /api/multi/{multipath}/description
Description: Change a multi's markdown description.
*/
func (sdk *ReddiGoSDK) PutMultiMultipathDescription(multipath string, model interface{}) (any, error) {
	reqUrl := fmt.Sprintf("/api/multi/%s/description", multipath)
	payload := map[string]interface{}{
		"model":     model,
		"multipath": multipath,
	}
	// Construct the request for PUT method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("PUT", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

// DeleteMultiMultipathRSrnameResponse represents the response for DELETE /api/multi/{multipath}/r/{srname}
type DeleteMultiMultipathRSrnameResponse struct {
	Multipath interface{} `json:"multipath"` // multireddit url path
	Srname    interface{} `json:"srname"`    // subreddit name
}

/*
DeleteMultiMultipathRSrname makes a DELETE request to /api/multi/{multipath}/r/{srname}
ID: DELETE /api/multi/{multipath}/r/{srname}
Description: Remove a subreddit from a multi.
*/
func (sdk *ReddiGoSDK) DeleteMultiMultipathRSrname(multipath string, srname string) (DeleteMultiMultipathRSrnameResponse, error) {
	reqUrl := fmt.Sprintf("/api/multi/%s/r/%s", multipath, srname)
	// Construct the request for DELETE method
	resp, err := sdk.MakeRequest("DELETE", reqUrl, nil)
	if err != nil {
		return DeleteMultiMultipathRSrnameResponse{}, err
	}
	defer resp.Body.Close()
	var response DeleteMultiMultipathRSrnameResponse
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return DeleteMultiMultipathRSrnameResponse{}, err
	}
	return response, nil
}

// GetMultiMultipathRSrnameResponse represents the response for GET /api/multi/{multipath}/r/{srname}
type GetMultiMultipathRSrnameResponse struct {
	Multipath interface{} `json:"multipath"` // multireddit url path
	Srname    interface{} `json:"srname"`    // subreddit name
}

/*
GetMultiMultipathRSrname makes a GET request to /api/multi/{multipath}/r/{srname}
ID: GET /api/multi/{multipath}/r/{srname}
Description: Get data about a subreddit in a multi.
*/
func (sdk *ReddiGoSDK) GetMultiMultipathRSrname(multipath string, srname string) (GetMultiMultipathRSrnameResponse, error) {
	reqUrl := fmt.Sprintf("/api/multi/%s/r/%s", multipath, srname)
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return GetMultiMultipathRSrnameResponse{}, err
	}
	defer resp.Body.Close()
	var response GetMultiMultipathRSrnameResponse
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return GetMultiMultipathRSrnameResponse{}, err
	}
	return response, nil
}

/*
PutMultiMultipathRSrname makes a PUT request to /api/multi/{multipath}/r/{srname}
ID: PUT /api/multi/{multipath}/r/{srname}
Description: Add a subreddit to a multi.
*/
func (sdk *ReddiGoSDK) PutMultiMultipathRSrname(multipath string, srname string, model interface{}) (any, error) {
	reqUrl := fmt.Sprintf("/api/multi/%s/r/%s", multipath, srname)
	payload := map[string]interface{}{
		"model":     model,
		"multipath": multipath,
		"srname":    srname,
	}
	// Construct the request for PUT method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("PUT", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

type GetRSubredditSearchSortEnum string

const (
	GetRSubredditSearchSortEnumRelevance GetRSubredditSearchSortEnum = "relevance"
	GetRSubredditSearchSortEnumHot       GetRSubredditSearchSortEnum = "hot"
	GetRSubredditSearchSortEnumTop       GetRSubredditSearchSortEnum = "top"
	GetRSubredditSearchSortEnumNew       GetRSubredditSearchSortEnum = "new"
	GetRSubredditSearchSortEnumComments  GetRSubredditSearchSortEnum = "comments"
)

type GetRSubredditSearchTEnum string

const (
	GetRSubredditSearchTEnumHour  GetRSubredditSearchTEnum = "hour"
	GetRSubredditSearchTEnumDay   GetRSubredditSearchTEnum = "day"
	GetRSubredditSearchTEnumWeek  GetRSubredditSearchTEnum = "week"
	GetRSubredditSearchTEnumMonth GetRSubredditSearchTEnum = "month"
	GetRSubredditSearchTEnumYear  GetRSubredditSearchTEnum = "year"
	GetRSubredditSearchTEnumAll   GetRSubredditSearchTEnum = "all"
)

// GetRSubredditSearchResponse represents the response for GET /r/{subreddit}/search
type GetRSubredditSearchResponse struct {
	After         string      `json:"after"`          // fullname of a thing
	Before        string      `json:"before"`         // fullname of a thing
	Category      string      `json:"category"`       // a string no longer than 5 characters
	Count         int         `json:"count"`          // a positive integer (default: 0)
	IncludeFacets bool        `json:"include_facets"` // boolean value
	Limit         interface{} `json:"limit"`          // the maximum number of items desired (default: 25, maximum: 100)
	Q             string      `json:"q"`              // a string no longer than 512 characters
	RestrictSr    bool        `json:"restrict_sr"`    // boolean value
	Show          string      `json:"show"`           // (optional) the string all
	Sort          string      `json:"sort"`           // one of (relevance, hot, top, new, comments)
	SrDetail      bool        `json:"sr_detail"`      // (optional) expand subreddits
	T             string      `json:"t"`              // one of (hour, day, week, month, year, all)
	TypeValue     interface{} `json:"type"`           // (optional) comma-delimited list of result types (sr, link, user)
}

/*
GetRSubredditSearch makes a GET request to /r/{subreddit}/search
ID: GET /r/{subreddit}/search
Description: Search links page.This endpoint is a listing.
*/
func (sdk *ReddiGoSDK) GetRSubredditSearch(subreddit string, after string, before string, count string, limit string) (GetRSubredditSearchResponse, error) {
	reqUrl := fmt.Sprintf("/r/%s/search", subreddit)
	queryParams := urlpkg.Values{}
	queryParams.Add("after", after)
	queryParams.Add("before", before)
	queryParams.Add("count", count)
	queryParams.Add("limit", limit)
	reqUrl += "?" + queryParams.Encode()
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return GetRSubredditSearchResponse{}, err
	}
	defer resp.Body.Close()
	var response GetRSubredditSearchResponse
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return GetRSubredditSearchResponse{}, err
	}
	return response, nil
}

// GetRSubredditAboutWhereResponse represents the response for GET /r/{subreddit}/about/{where}
type GetRSubredditAboutWhereResponse struct {
	After    string      `json:"after"`     // fullname of a thing
	Before   string      `json:"before"`    // fullname of a thing
	Count    int         `json:"count"`     // a positive integer (default: 0)
	Limit    interface{} `json:"limit"`     // the maximum number of items desired (default: 25, maximum: 100)
	Show     string      `json:"show"`      // (optional) the string all
	SrDetail bool        `json:"sr_detail"` // (optional) expand subreddits
	User     interface{} `json:"user"`      // A valid, existing reddit username
}

/*
GetRSubredditAboutWhere makes a GET request to /r/{subreddit}/about/{where}
ID: GET /r/{subreddit}/about/{where}
Description: This endpoint is a listing.
*/
func (sdk *ReddiGoSDK) GetRSubredditAboutWhere(subreddit string, where string, after string, before string, count string, limit string) (GetRSubredditAboutWhereResponse, error) {
	reqUrl := fmt.Sprintf("/r/%s/about/%s", subreddit, where)
	queryParams := urlpkg.Values{}
	queryParams.Add("after", after)
	queryParams.Add("before", before)
	queryParams.Add("count", count)
	queryParams.Add("limit", limit)
	reqUrl += "?" + queryParams.Encode()
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return GetRSubredditAboutWhereResponse{}, err
	}
	defer resp.Body.Close()
	var response GetRSubredditAboutWhereResponse
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return GetRSubredditAboutWhereResponse{}, err
	}
	return response, nil
}

/*
PostRSubredditDeleteSrBanner makes a POST request to /r/{subreddit}/api/delete_sr_banner
ID: POST /r/{subreddit}/api/delete_sr_banner
Description: Remove the subreddit's custom mobile banner.See also: /api/upload_sr_img.
*/
func (sdk *ReddiGoSDK) PostRSubredditDeleteSrBanner(subreddit string, apiType string) (any, error) {
	reqUrl := fmt.Sprintf("/r/%s/api/delete_sr_banner", subreddit)
	payload := map[string]interface{}{
		"api_type": apiType,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostRSubredditDeleteSrHeader makes a POST request to /r/{subreddit}/api/delete_sr_header
ID: POST /r/{subreddit}/api/delete_sr_header
Description: Remove the subreddit's custom header image.The sitewide-default header image will be shown again after this call.See also: /api/upload_sr_img.
*/
func (sdk *ReddiGoSDK) PostRSubredditDeleteSrHeader(subreddit string, apiType string) (any, error) {
	reqUrl := fmt.Sprintf("/r/%s/api/delete_sr_header", subreddit)
	payload := map[string]interface{}{
		"api_type": apiType,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostRSubredditDeleteSrIcon makes a POST request to /r/{subreddit}/api/delete_sr_icon
ID: POST /r/{subreddit}/api/delete_sr_icon
Description: Remove the subreddit's custom mobile icon.See also: /api/upload_sr_img.
*/
func (sdk *ReddiGoSDK) PostRSubredditDeleteSrIcon(subreddit string, apiType string) (any, error) {
	reqUrl := fmt.Sprintf("/r/%s/api/delete_sr_icon", subreddit)
	payload := map[string]interface{}{
		"api_type": apiType,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostRSubredditDeleteSrImg makes a POST request to /r/{subreddit}/api/delete_sr_img
ID: POST /r/{subreddit}/api/delete_sr_img
Description: Remove an image from the subreddit's custom image set.The image will no longer count against the subreddit's image limit.
However, the actual image data may still be accessible for an
unspecified amount of time. If the image is currently referenced by the
subreddit's stylesheet, that stylesheet will no longer validate and
won't be editable until the image reference is removed.See also: /api/upload_sr_img.
*/
func (sdk *ReddiGoSDK) PostRSubredditDeleteSrImg(subreddit string, apiType string, imgName interface{}) (any, error) {
	reqUrl := fmt.Sprintf("/r/%s/api/delete_sr_img", subreddit)
	payload := map[string]interface{}{
		"api_type": apiType,
		"img_name": imgName,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

// GetRecommendSrSrnamesResponse represents the response for GET /api/recommend/sr/{srnames}
type GetRecommendSrSrnamesResponse struct {
	Omit    interface{} `json:"omit"`    // comma-delimited list of subreddit names
	Over18  bool        `json:"over_18"` // boolean value
	Srnames interface{} `json:"srnames"` // comma-delimited list of subreddit names
}

/*
GetRecommendSrSrnames makes a GET request to /api/recommend/sr/{srnames}
ID: GET /api/recommend/sr/{srnames}
Description: DEPRECATED: Return subreddits recommended for the given subreddit(s).Gets a list of subreddits recommended for srnames, filtering out any
that appear in the optional omit param.
*/
func (sdk *ReddiGoSDK) GetRecommendSrSrnames(srnames string) (GetRecommendSrSrnamesResponse, error) {
	reqUrl := fmt.Sprintf("/api/recommend/sr/%s", srnames)
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return GetRecommendSrSrnamesResponse{}, err
	}
	defer resp.Body.Close()
	var response GetRecommendSrSrnamesResponse
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return GetRecommendSrSrnamesResponse{}, err
	}
	return response, nil
}

// GetSearchRedditNamesResponse represents the response for GET /api/search_reddit_names
type GetSearchRedditNamesResponse struct {
	Exact                 bool        `json:"exact"`                  // boolean value
	IncludeOver18         bool        `json:"include_over_18"`        // boolean value
	IncludeUnadvertisable bool        `json:"include_unadvertisable"` // boolean value
	Query                 string      `json:"query"`                  // a string up to 50 characters long, consisting of printable characters.
	SearchQueryId         interface{} `json:"search_query_id"`        // a uuid
	TypeaheadActive       bool        `json:"typeahead_active"`       // boolean value or None
}

/*
GetSearchRedditNames makes a GET request to /api/search_reddit_names
ID: GET /api/search_reddit_names
Description: List subreddit names that begin with a query string.Subreddits whose names begin with query will be returned. If
include_over_18 is false, subreddits with over-18 content
restrictions will be filtered from the results.If include_unadvertisable is False, subreddits that have hide_ads
set to True or are on the anti_ads_subreddits list will be filtered.If exact is true, only an exact match will be returned. Exact matches
are inclusive of over_18 subreddits, but not hide_ad subreddits
when include_unadvertisable is False.
*/
func (sdk *ReddiGoSDK) GetSearchRedditNames() (GetSearchRedditNamesResponse, error) {
	reqUrl := "/api/search_reddit_names"
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return GetSearchRedditNamesResponse{}, err
	}
	defer resp.Body.Close()
	var response GetSearchRedditNamesResponse
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return GetSearchRedditNamesResponse{}, err
	}
	return response, nil
}

/*
PostSearchRedditNames makes a POST request to /api/search_reddit_names
ID: POST /api/search_reddit_names
Description: List subreddit names that begin with a query string.Subreddits whose names begin with query will be returned. If
include_over_18 is false, subreddits with over-18 content
restrictions will be filtered from the results.If include_unadvertisable is False, subreddits that have hide_ads
set to True or are on the anti_ads_subreddits list will be filtered.If exact is true, only an exact match will be returned. Exact matches
are inclusive of over_18 subreddits, but not hide_ad subreddits
when include_unadvertisable is False.
*/
func (sdk *ReddiGoSDK) PostSearchRedditNames(exact bool, includeOver18 bool, includeUnadvertisable bool, query string, searchQueryId interface{}, typeaheadActive bool) (any, error) {
	reqUrl := "/api/search_reddit_names"
	payload := map[string]interface{}{
		"exact":                  exact,
		"include_over_18":        includeOver18,
		"include_unadvertisable": includeUnadvertisable,
		"query":                  query,
		"search_query_id":        searchQueryId,
		"typeahead_active":       typeaheadActive,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostSearchSubreddits makes a POST request to /api/search_subreddits
ID: POST /api/search_subreddits
Description: List subreddits that begin with a query string.Subreddits whose names begin with query will be returned. If
include_over_18 is false, subreddits with over-18 content
restrictions will be filtered from the results.If include_unadvertisable is False, subreddits that have hide_ads
set to True or are on the anti_ads_subreddits list will be filtered.If exact is true, only an exact match will be returned. Exact matches
are inclusive of over_18 subreddits, but not hide_ad subreddits
when include_unadvertisable is False.
*/
func (sdk *ReddiGoSDK) PostSearchSubreddits(exact bool, includeOver18 bool, includeUnadvertisable bool, query string, searchQueryId interface{}, typeaheadActive bool) (any, error) {
	reqUrl := "/api/search_subreddits"
	payload := map[string]interface{}{
		"exact":                  exact,
		"include_over_18":        includeOver18,
		"include_unadvertisable": includeUnadvertisable,
		"query":                  query,
		"search_query_id":        searchQueryId,
		"typeahead_active":       typeaheadActive,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

type PostSiteAdminLinkTypeEnum string

const (
	PostSiteAdminLinkTypeEnumAny  PostSiteAdminLinkTypeEnum = "any"
	PostSiteAdminLinkTypeEnumLink PostSiteAdminLinkTypeEnum = "link"
	PostSiteAdminLinkTypeEnumSelf PostSiteAdminLinkTypeEnum = "self"
)

type PostSiteAdminSpamCommentsEnum string

const (
	PostSiteAdminSpamCommentsEnumLow  PostSiteAdminSpamCommentsEnum = "low"
	PostSiteAdminSpamCommentsEnumHigh PostSiteAdminSpamCommentsEnum = "high"
	PostSiteAdminSpamCommentsEnumAll  PostSiteAdminSpamCommentsEnum = "all"
)

type PostSiteAdminSpamLinksEnum string

const (
	PostSiteAdminSpamLinksEnumLow  PostSiteAdminSpamLinksEnum = "low"
	PostSiteAdminSpamLinksEnumHigh PostSiteAdminSpamLinksEnum = "high"
	PostSiteAdminSpamLinksEnumAll  PostSiteAdminSpamLinksEnum = "all"
)

type PostSiteAdminSpamSelfpostsEnum string

const (
	PostSiteAdminSpamSelfpostsEnumLow  PostSiteAdminSpamSelfpostsEnum = "low"
	PostSiteAdminSpamSelfpostsEnumHigh PostSiteAdminSpamSelfpostsEnum = "high"
	PostSiteAdminSpamSelfpostsEnumAll  PostSiteAdminSpamSelfpostsEnum = "all"
)

type PostSiteAdminSuggestedCommentSortEnum string

const (
	PostSiteAdminSuggestedCommentSortEnumConfidence    PostSiteAdminSuggestedCommentSortEnum = "confidence"
	PostSiteAdminSuggestedCommentSortEnumTop           PostSiteAdminSuggestedCommentSortEnum = "top"
	PostSiteAdminSuggestedCommentSortEnumNew           PostSiteAdminSuggestedCommentSortEnum = "new"
	PostSiteAdminSuggestedCommentSortEnumControversial PostSiteAdminSuggestedCommentSortEnum = "controversial"
	PostSiteAdminSuggestedCommentSortEnumOld           PostSiteAdminSuggestedCommentSortEnum = "old"
	PostSiteAdminSuggestedCommentSortEnumRandom        PostSiteAdminSuggestedCommentSortEnum = "random"
	PostSiteAdminSuggestedCommentSortEnumQa            PostSiteAdminSuggestedCommentSortEnum = "qa"
	PostSiteAdminSuggestedCommentSortEnumLive          PostSiteAdminSuggestedCommentSortEnum = "live"
)

type PostSiteAdminTypeEnum string

const (
	PostSiteAdminTypeEnumGold_restricted PostSiteAdminTypeEnum = "gold_restricted"
	PostSiteAdminTypeEnumArchived        PostSiteAdminTypeEnum = "archived"
	PostSiteAdminTypeEnumRestricted      PostSiteAdminTypeEnum = "restricted"
	PostSiteAdminTypeEnumPrivate         PostSiteAdminTypeEnum = "private"
	PostSiteAdminTypeEnumEmployees_only  PostSiteAdminTypeEnum = "employees_only"
	PostSiteAdminTypeEnumGold_only       PostSiteAdminTypeEnum = "gold_only"
	PostSiteAdminTypeEnumPublic          PostSiteAdminTypeEnum = "public"
	PostSiteAdminTypeEnumUser            PostSiteAdminTypeEnum = "user"
)

type PostSiteAdminWikimodeEnum string

const (
	PostSiteAdminWikimodeEnumDisabled PostSiteAdminWikimodeEnum = "disabled"
	PostSiteAdminWikimodeEnumModonly  PostSiteAdminWikimodeEnum = "modonly"
	PostSiteAdminWikimodeEnumAnyone   PostSiteAdminWikimodeEnum = "anyone"
)

/*
PostSiteAdmin makes a POST request to /api/site_admin
ID: POST /api/site_admin
Description: Create or configure a subreddit.If sr is specified, the request will attempt to modify the specified
subreddit. If not, a subreddit with name name will be created.This endpoint expects all values to be supplied on every request.  If
modifying a subset of options, it may be useful to get the current
settings from /about/edit.json
first.For backwards compatibility, description is the sidebar text and
public_description is the publicly visible subreddit description.Most of the parameters for this endpoint are identical to options
visible in the user interface and their meanings are best explained
there.See also: /about/edit.json.
*/
func (sdk *ReddiGoSDK) PostSiteAdmin(acceptFollowers bool, adminOverrideSpamComments bool, adminOverrideSpamLinks bool, adminOverrideSpamSelfposts bool, allOriginalContent bool, allowChatPostCreation bool, allowDiscovery bool, allowGalleries bool, allowImages bool, allowPolls bool, allowPostCrossposts bool, allowPredictionContributors bool, allowPredictions bool, allowPredictionsTournament bool, allowTalks bool, allowTop bool, allowVideos bool, apiType string, collapseDeletedComments bool, commentContributionSettings interface{}, commentScoreHideMins int, crowdControlChatLevel int, crowdControlFilter bool, crowdControlLevel int, crowdControlMode bool, crowdControlPostLevel int, description interface{}, disableContributorRequests bool, excludeBannedModqueue bool, freeFormReports bool, gRecaptchaResponse interface{}, hatefulContentThresholdAbuse int, hatefulContentThresholdIdentity int, hideAds bool, keyColor interface{}, linkType string, modmailHarassmentFilterEnabled bool, name interface{}, newPinnedPostPnsEnabled bool, originalContentTagEnabled bool, over18 bool, predictionLeaderboardEntryType int, publicDescription interface{}, restrictCommenting bool, restrictPosting bool, shouldArchivePosts bool, showMedia bool, showMediaPreview bool, spamComments string, spamLinks string, spamSelfposts string, spoilersEnabled bool, sr string, submitLinkLabel string, submitText interface{}, submitTextLabel string, subredditDiscoverySettings interface{}, suggestedCommentSort string, title string, toxicityThresholdChatLevel int, typeValue string, userFlairPnsEnabled bool, welcomeMessageEnabled bool, welcomeMessageText interface{}, wikiEditAge int, wikiEditKarma int, wikimode string) (any, error) {
	reqUrl := "/api/site_admin"
	payload := map[string]interface{}{
		"accept_followers":                   acceptFollowers,
		"admin_override_spam_comments":       adminOverrideSpamComments,
		"admin_override_spam_links":          adminOverrideSpamLinks,
		"admin_override_spam_selfposts":      adminOverrideSpamSelfposts,
		"all_original_content":               allOriginalContent,
		"allow_chat_post_creation":           allowChatPostCreation,
		"allow_discovery":                    allowDiscovery,
		"allow_galleries":                    allowGalleries,
		"allow_images":                       allowImages,
		"allow_polls":                        allowPolls,
		"allow_post_crossposts":              allowPostCrossposts,
		"allow_prediction_contributors":      allowPredictionContributors,
		"allow_predictions":                  allowPredictions,
		"allow_predictions_tournament":       allowPredictionsTournament,
		"allow_talks":                        allowTalks,
		"allow_top":                          allowTop,
		"allow_videos":                       allowVideos,
		"api_type":                           apiType,
		"collapse_deleted_comments":          collapseDeletedComments,
		"comment_contribution_settings":      commentContributionSettings,
		"comment_score_hide_mins":            commentScoreHideMins,
		"crowd_control_chat_level":           crowdControlChatLevel,
		"crowd_control_filter":               crowdControlFilter,
		"crowd_control_level":                crowdControlLevel,
		"crowd_control_mode":                 crowdControlMode,
		"crowd_control_post_level":           crowdControlPostLevel,
		"description":                        description,
		"disable_contributor_requests":       disableContributorRequests,
		"exclude_banned_modqueue":            excludeBannedModqueue,
		"free_form_reports":                  freeFormReports,
		"g-recaptcha-response":               gRecaptchaResponse,
		"hateful_content_threshold_abuse":    hatefulContentThresholdAbuse,
		"hateful_content_threshold_identity": hatefulContentThresholdIdentity,
		"hide_ads":                           hideAds,
		"key_color":                          keyColor,
		"link_type":                          linkType,
		"modmail_harassment_filter_enabled":  modmailHarassmentFilterEnabled,
		"name":                               name,
		"new_pinned_post_pns_enabled":        newPinnedPostPnsEnabled,
		"original_content_tag_enabled":       originalContentTagEnabled,
		"over_18":                            over18,
		"prediction_leaderboard_entry_type":  predictionLeaderboardEntryType,
		"public_description":                 publicDescription,
		"restrict_commenting":                restrictCommenting,
		"restrict_posting":                   restrictPosting,
		"should_archive_posts":               shouldArchivePosts,
		"show_media":                         showMedia,
		"show_media_preview":                 showMediaPreview,
		"spam_comments":                      spamComments,
		"spam_links":                         spamLinks,
		"spam_selfposts":                     spamSelfposts,
		"spoilers_enabled":                   spoilersEnabled,
		"sr":                                 sr,
		"submit_link_label":                  submitLinkLabel,
		"submit_text":                        submitText,
		"submit_text_label":                  submitTextLabel,
		"subreddit_discovery_settings":       subredditDiscoverySettings,
		"suggested_comment_sort":             suggestedCommentSort,
		"title":                              title,
		"toxicity_threshold_chat_level":      toxicityThresholdChatLevel,
		"type":                               typeValue,
		"user_flair_pns_enabled":             userFlairPnsEnabled,
		"welcome_message_enabled":            welcomeMessageEnabled,
		"welcome_message_text":               welcomeMessageText,
		"wiki_edit_age":                      wikiEditAge,
		"wiki_edit_karma":                    wikiEditKarma,
		"wikimode":                           wikimode,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
GetRSubredditSubmitText makes a GET request to /r/{subreddit}/api/submit_text
ID: GET /r/{subreddit}/api/submit_text
Description: Get the submission text for the subreddit.This text is set by the subreddit moderators and intended to be
displayed on the submission form.See also: /api/site_admin.
*/
func (sdk *ReddiGoSDK) GetRSubredditSubmitText(subreddit string) (any, error) {
	reqUrl := fmt.Sprintf("/r/%s/api/submit_text", subreddit)
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

// GetSubredditAutocompleteResponse represents the response for GET /api/subreddit_autocomplete
type GetSubredditAutocompleteResponse struct {
	IncludeOver18   bool   `json:"include_over_18"`  // boolean value
	IncludeProfiles bool   `json:"include_profiles"` // boolean value
	Query           string `json:"query"`            // a string up to 25 characters long, consisting of printable characters.
}

/*
GetSubredditAutocomplete makes a GET request to /api/subreddit_autocomplete
ID: GET /api/subreddit_autocomplete
Description: Return a list of subreddits and data for subreddits whose names start
with 'query'.Uses typeahead endpoint to recieve the list of subreddits names.
Typeahead provides exact matches, typo correction, fuzzy matching and
boosts subreddits to the top that the user is subscribed to.
*/
func (sdk *ReddiGoSDK) GetSubredditAutocomplete() (GetSubredditAutocompleteResponse, error) {
	reqUrl := "/api/subreddit_autocomplete"
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return GetSubredditAutocompleteResponse{}, err
	}
	defer resp.Body.Close()
	var response GetSubredditAutocompleteResponse
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return GetSubredditAutocompleteResponse{}, err
	}
	return response, nil
}

// GetSubredditAutocompleteV2Response represents the response for GET /api/subreddit_autocomplete_v2
type GetSubredditAutocompleteV2Response struct {
	IncludeOver18   bool        `json:"include_over_18"`  // boolean value
	IncludeProfiles bool        `json:"include_profiles"` // boolean value
	Limit           int         `json:"limit"`            // an integer between 1 and 10 (default: 5)
	Query           string      `json:"query"`            // a string up to 25 characters long, consisting of printable characters.
	SearchQueryId   interface{} `json:"search_query_id"`  // a uuid
	TypeaheadActive bool        `json:"typeahead_active"` // boolean value or None
}

/*
GetSubredditAutocompleteV2 makes a GET request to /api/subreddit_autocomplete_v2
ID: GET /api/subreddit_autocomplete_v2
Description: No description available
*/
func (sdk *ReddiGoSDK) GetSubredditAutocompleteV2(limit string) (GetSubredditAutocompleteV2Response, error) {
	reqUrl := "/api/subreddit_autocomplete_v2"
	queryParams := urlpkg.Values{}
	queryParams.Add("limit", limit)
	reqUrl += "?" + queryParams.Encode()
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return GetSubredditAutocompleteV2Response{}, err
	}
	defer resp.Body.Close()
	var response GetSubredditAutocompleteV2Response
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return GetSubredditAutocompleteV2Response{}, err
	}
	return response, nil
}

type PostRSubredditSubredditStylesheetOpEnum string

const (
	PostRSubredditSubredditStylesheetOpEnumSave    PostRSubredditSubredditStylesheetOpEnum = "save"
	PostRSubredditSubredditStylesheetOpEnumPreview PostRSubredditSubredditStylesheetOpEnum = "preview"
)

/*
PostRSubredditSubredditStylesheet makes a POST request to /r/{subreddit}/api/{subreddit}_stylesheet
ID: POST /r/{subreddit}/api/{subreddit}_stylesheet
Description: Update a subreddit's stylesheet.op should be save to update the contents of the stylesheet.
*/
func (sdk *ReddiGoSDK) PostRSubredditSubredditStylesheet(subreddit string, apiType string, op string, reason string, stylesheetContents interface{}) (any, error) {
	reqUrl := fmt.Sprintf("/r/%s/api/%s_stylesheet", subreddit, subreddit)
	payload := map[string]interface{}{
		"api_type":            apiType,
		"op":                  op,
		"reason":              reason,
		"stylesheet_contents": stylesheetContents,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

type PostSubscribeActionEnum string

const (
	PostSubscribeActionEnumSub   PostSubscribeActionEnum = "sub"
	PostSubscribeActionEnumUnsub PostSubscribeActionEnum = "unsub"
)

type PostSubscribeActionSourceEnum string

const (
	PostSubscribeActionSourceEnumOnboarding    PostSubscribeActionSourceEnum = "onboarding"
	PostSubscribeActionSourceEnumAutosubscribe PostSubscribeActionSourceEnum = "autosubscribe"
)

/*
PostSubscribe makes a POST request to /api/subscribe
ID: POST /api/subscribe
Description: Subscribe to or unsubscribe from a subreddit.To subscribe, action should be sub. To unsubscribe, action should
be unsub. The user must have access to the subreddit to be able to
subscribe to it.The skip_initial_defaults param can be set to True to prevent
automatically subscribing the user to the current set of defaults
when they take their first subscription action. Attempting to set it
for an unsubscribe action will result in an error.See also: /subreddits/mine/.
*/
func (sdk *ReddiGoSDK) PostSubscribe(action string, actionSource string, skipInitialDefaults bool, sr string) (any, error) {
	reqUrl := "/api/subscribe"
	payload := map[string]interface{}{
		"action":                action,
		"action_source":         actionSource,
		"skip_initial_defaults": skipInitialDefaults,
		"sr":                    sr,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

type PostRSubredditUploadSrImgUploadTypeEnum string

const (
	PostRSubredditUploadSrImgUploadTypeEnumImg    PostRSubredditUploadSrImgUploadTypeEnum = "img"
	PostRSubredditUploadSrImgUploadTypeEnumHeader PostRSubredditUploadSrImgUploadTypeEnum = "header"
	PostRSubredditUploadSrImgUploadTypeEnumIcon   PostRSubredditUploadSrImgUploadTypeEnum = "icon"
	PostRSubredditUploadSrImgUploadTypeEnumBanner PostRSubredditUploadSrImgUploadTypeEnum = "banner"
)

/*
PostRSubredditUploadSrImg makes a POST request to /r/{subreddit}/api/upload_sr_img
ID: POST /r/{subreddit}/api/upload_sr_img
Description: Add or replace a subreddit image, custom header logo, custom mobile
icon, or custom mobile banner.For backwards compatibility, if upload_type is not specified, the
header field will be used instead:The img_type field specifies whether to store the uploaded image as a
PNG or JPEG.Subreddits have a limited number of images that can be in use at any
given time. If no image with the specified name already exists, one of
the slots will be consumed.If an image with the specified name already exists, it will be
replaced.  This does not affect the stylesheet immediately, but will
take effect the next time the stylesheet is saved.See also: /api/delete_sr_img,
/api/delete_sr_header,
/api/delete_sr_icon, and
/api/delete_sr_banner.
*/
func (sdk *ReddiGoSDK) PostRSubredditUploadSrImg(subreddit string, file interface{}, formid interface{}, imgType interface{}, name interface{}, uploadType string) (any, error) {
	reqUrl := fmt.Sprintf("/r/%s/api/upload_sr_img", subreddit)
	payload := map[string]interface{}{
		"file":        file,
		"formid":      formid,
		"img_type":    imgType,
		"name":        name,
		"upload_type": uploadType,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
GetSubredditPostRequirements makes a GET request to /api/v1/{subreddit}/post_requirements
ID: GET /api/v1/{subreddit}/post_requirements
Description: Fetch moderator-designated requirements to post to the subreddit.Moderators may enable certain restrictions, such as minimum title
length, when making a submission to their subreddit.Clients may use the values returned by this endpoint to pre-validate
fields before making a request to POST /api/submit. This may allow
the client to provide a better user experience to the user, for
example by creating a text field in their app that does not allow
the user to enter more characters than the max title length.A non-exhaustive list of possible requirements a moderator may
enable:
*/
func (sdk *ReddiGoSDK) GetSubredditPostRequirements(subreddit string) (any, error) {
	reqUrl := fmt.Sprintf("/api/v1/%s/post_requirements", subreddit)
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
GetRSubredditAbout makes a GET request to /r/{subreddit}/about
ID: GET /r/{subreddit}/about
Description: Return information about the subreddit.Data includes the subscriber count, description, and header image.
*/
func (sdk *ReddiGoSDK) GetRSubredditAbout(subreddit string) (any, error) {
	reqUrl := fmt.Sprintf("/r/%s/about", subreddit)
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

type GetRSubredditAboutEditCreatedEnum string

const (
	GetRSubredditAboutEditCreatedEnumTrue  GetRSubredditAboutEditCreatedEnum = "true"
	GetRSubredditAboutEditCreatedEnumFalse GetRSubredditAboutEditCreatedEnum = "false"
)

// GetRSubredditAboutEditResponse represents the response for GET /r/{subreddit}/about/edit
type GetRSubredditAboutEditResponse struct {
	Created  string      `json:"created"`  // one of (true, false)
	Location interface{} `json:"location"` //
}

/*
GetRSubredditAboutEdit makes a GET request to /r/{subreddit}/about/edit
ID: GET /r/{subreddit}/about/edit
Description: Get the current settings of a subreddit.In the API, this returns the current settings of the subreddit as used
by /api/site_admin.  On the HTML site, it will
display a form for editing the subreddit.
*/
func (sdk *ReddiGoSDK) GetRSubredditAboutEdit(subreddit string) (GetRSubredditAboutEditResponse, error) {
	reqUrl := fmt.Sprintf("/r/%s/about/edit", subreddit)
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return GetRSubredditAboutEditResponse{}, err
	}
	defer resp.Body.Close()
	var response GetRSubredditAboutEditResponse
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return GetRSubredditAboutEditResponse{}, err
	}
	return response, nil
}

/*
GetRSubredditAboutRules makes a GET request to /r/{subreddit}/about/rules
ID: GET /r/{subreddit}/about/rules
Description: Get the rules for the current subreddit
*/
func (sdk *ReddiGoSDK) GetRSubredditAboutRules(subreddit string) (any, error) {
	reqUrl := fmt.Sprintf("/r/%s/about/rules", subreddit)
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
GetRSubredditAboutTraffic makes a GET request to /r/{subreddit}/about/traffic
ID: GET /r/{subreddit}/about/traffic
Description: No description available
*/
func (sdk *ReddiGoSDK) GetRSubredditAboutTraffic(subreddit string) (any, error) {
	reqUrl := fmt.Sprintf("/r/%s/about/traffic", subreddit)
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
GetRSubredditSidebar makes a GET request to /r/{subreddit}/sidebar
ID: GET /r/{subreddit}/sidebar
Description: Get the sidebar for the current subreddit
*/
func (sdk *ReddiGoSDK) GetRSubredditSidebar(subreddit string) (any, error) {
	reqUrl := fmt.Sprintf("/r/%s/sidebar", subreddit)
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

// GetRSubredditStickyResponse represents the response for GET /r/{subreddit}/sticky
type GetRSubredditStickyResponse struct {
	Num int `json:"num"` // an integer between 1 and 2 (default: 1)
}

/*
GetRSubredditSticky makes a GET request to /r/{subreddit}/sticky
ID: GET /r/{subreddit}/sticky
Description: Redirect to one of the posts stickied in the current subredditThe "num" argument can be used to select a specific sticky, and will
default to 1 (the top sticky) if not specified.
Will 404 if there is not currently a sticky post in this subreddit.
*/
func (sdk *ReddiGoSDK) GetRSubredditSticky(subreddit string) (GetRSubredditStickyResponse, error) {
	reqUrl := fmt.Sprintf("/r/%s/sticky", subreddit)
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return GetRSubredditStickyResponse{}, err
	}
	defer resp.Body.Close()
	var response GetRSubredditStickyResponse
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return GetRSubredditStickyResponse{}, err
	}
	return response, nil
}

// GetSubredditsMineWhereResponse represents the response for GET /subreddits/mine/{where}
type GetSubredditsMineWhereResponse struct {
	After    string      `json:"after"`     // fullname of a thing
	Before   string      `json:"before"`    // fullname of a thing
	Count    int         `json:"count"`     // a positive integer (default: 0)
	Limit    interface{} `json:"limit"`     // the maximum number of items desired (default: 25, maximum: 100)
	Show     string      `json:"show"`      // (optional) the string all
	SrDetail bool        `json:"sr_detail"` // (optional) expand subreddits
}

/*
GetSubredditsMineWhere makes a GET request to /subreddits/mine/{where}
ID: GET /subreddits/mine/{where}
Description: Get subreddits the user has a relationship with.The where parameter chooses which subreddits are returned as follows:See also: /api/subscribe,
/api/friend, and
/api/accept_moderator_invite.This endpoint is a listing.
*/
func (sdk *ReddiGoSDK) GetSubredditsMineWhere(where string, after string, before string, count string, limit string) (GetSubredditsMineWhereResponse, error) {
	reqUrl := fmt.Sprintf("/subreddits/mine/%s", where)
	queryParams := urlpkg.Values{}
	queryParams.Add("after", after)
	queryParams.Add("before", before)
	queryParams.Add("count", count)
	queryParams.Add("limit", limit)
	reqUrl += "?" + queryParams.Encode()
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return GetSubredditsMineWhereResponse{}, err
	}
	defer resp.Body.Close()
	var response GetSubredditsMineWhereResponse
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return GetSubredditsMineWhereResponse{}, err
	}
	return response, nil
}

type GetSubredditsSearchSortEnum string

const (
	GetSubredditsSearchSortEnumRelevance GetSubredditsSearchSortEnum = "relevance"
	GetSubredditsSearchSortEnumActivity  GetSubredditsSearchSortEnum = "activity"
)

// GetSubredditsSearchResponse represents the response for GET /subreddits/search
type GetSubredditsSearchResponse struct {
	After           string      `json:"after"`            // fullname of a thing
	Before          string      `json:"before"`           // fullname of a thing
	Count           int         `json:"count"`            // a positive integer (default: 0)
	Limit           interface{} `json:"limit"`            // the maximum number of items desired (default: 25, maximum: 100)
	Q               interface{} `json:"q"`                // a search query
	SearchQueryId   interface{} `json:"search_query_id"`  // a uuid
	Show            string      `json:"show"`             // (optional) the string all
	ShowUsers       bool        `json:"show_users"`       // boolean value
	Sort            string      `json:"sort"`             // one of (relevance, activity)
	SrDetail        bool        `json:"sr_detail"`        // (optional) expand subreddits
	TypeaheadActive bool        `json:"typeahead_active"` // boolean value or None
}

/*
GetSubredditsSearch makes a GET request to /subreddits/search
ID: GET /subreddits/search
Description: Search subreddits by title and description.This endpoint is a listing.
*/
func (sdk *ReddiGoSDK) GetSubredditsSearch(after string, before string, count string, limit string) (GetSubredditsSearchResponse, error) {
	reqUrl := "/subreddits/search"
	queryParams := urlpkg.Values{}
	queryParams.Add("after", after)
	queryParams.Add("before", before)
	queryParams.Add("count", count)
	queryParams.Add("limit", limit)
	reqUrl += "?" + queryParams.Encode()
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return GetSubredditsSearchResponse{}, err
	}
	defer resp.Body.Close()
	var response GetSubredditsSearchResponse
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return GetSubredditsSearchResponse{}, err
	}
	return response, nil
}

// GetSubredditsWhereResponse represents the response for GET /subreddits/{where}
type GetSubredditsWhereResponse struct {
	After    string      `json:"after"`     // fullname of a thing
	Before   string      `json:"before"`    // fullname of a thing
	Count    int         `json:"count"`     // a positive integer (default: 0)
	Limit    interface{} `json:"limit"`     // the maximum number of items desired (default: 25, maximum: 100)
	Show     string      `json:"show"`      // (optional) the string all
	SrDetail bool        `json:"sr_detail"` // (optional) expand subreddits
}

/*
GetSubredditsWhere makes a GET request to /subreddits/{where}
ID: GET /subreddits/{where}
Description: Get all subreddits.The where parameter chooses the order in which the subreddits are
displayed.  popular sorts on the activity of the subreddit and the
position of the subreddits can shift around. new sorts the subreddits
based on their creation date, newest first.This endpoint is a listing.
*/
func (sdk *ReddiGoSDK) GetSubredditsWhere(where string, after string, before string, count string, limit string) (GetSubredditsWhereResponse, error) {
	reqUrl := fmt.Sprintf("/subreddits/%s", where)
	queryParams := urlpkg.Values{}
	queryParams.Add("after", after)
	queryParams.Add("before", before)
	queryParams.Add("count", count)
	queryParams.Add("limit", limit)
	reqUrl += "?" + queryParams.Encode()
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return GetSubredditsWhereResponse{}, err
	}
	defer resp.Body.Close()
	var response GetSubredditsWhereResponse
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return GetSubredditsWhereResponse{}, err
	}
	return response, nil
}

type GetUsersSearchSortEnum string

const (
	GetUsersSearchSortEnumRelevance GetUsersSearchSortEnum = "relevance"
	GetUsersSearchSortEnumActivity  GetUsersSearchSortEnum = "activity"
)

// GetUsersSearchResponse represents the response for GET /users/search
type GetUsersSearchResponse struct {
	After           string      `json:"after"`            // fullname of a thing
	Before          string      `json:"before"`           // fullname of a thing
	Count           int         `json:"count"`            // a positive integer (default: 0)
	Limit           interface{} `json:"limit"`            // the maximum number of items desired (default: 25, maximum: 100)
	Q               interface{} `json:"q"`                // a search query
	SearchQueryId   interface{} `json:"search_query_id"`  // a uuid
	Show            string      `json:"show"`             // (optional) the string all
	Sort            string      `json:"sort"`             // one of (relevance, activity)
	SrDetail        bool        `json:"sr_detail"`        // (optional) expand subreddits
	TypeaheadActive bool        `json:"typeahead_active"` // boolean value or None
}

/*
GetUsersSearch makes a GET request to /users/search
ID: GET /users/search
Description: Search user profiles by title and description.This endpoint is a listing.
*/
func (sdk *ReddiGoSDK) GetUsersSearch(after string, before string, count string, limit string) (GetUsersSearchResponse, error) {
	reqUrl := "/users/search"
	queryParams := urlpkg.Values{}
	queryParams.Add("after", after)
	queryParams.Add("before", before)
	queryParams.Add("count", count)
	queryParams.Add("limit", limit)
	reqUrl += "?" + queryParams.Encode()
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return GetUsersSearchResponse{}, err
	}
	defer resp.Body.Close()
	var response GetUsersSearchResponse
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return GetUsersSearchResponse{}, err
	}
	return response, nil
}

// GetUsersWhereResponse represents the response for GET /users/{where}
type GetUsersWhereResponse struct {
	After    string      `json:"after"`     // fullname of a thing
	Before   string      `json:"before"`    // fullname of a thing
	Count    int         `json:"count"`     // a positive integer (default: 0)
	Limit    interface{} `json:"limit"`     // the maximum number of items desired (default: 25, maximum: 100)
	Show     string      `json:"show"`      // (optional) the string all
	SrDetail bool        `json:"sr_detail"` // (optional) expand subreddits
}

/*
GetUsersWhere makes a GET request to /users/{where}
ID: GET /users/{where}
Description: Get all user subreddits.The where parameter chooses the order in which the subreddits are
displayed. popular sorts on the activity of the subreddit and the
position of the subreddits can shift around. new sorts the user
subreddits based on their creation date, newest first.This endpoint is a listing.
*/
func (sdk *ReddiGoSDK) GetUsersWhere(where string, after string, before string, count string, limit string) (GetUsersWhereResponse, error) {
	reqUrl := fmt.Sprintf("/users/%s", where)
	queryParams := urlpkg.Values{}
	queryParams.Add("after", after)
	queryParams.Add("before", before)
	queryParams.Add("count", count)
	queryParams.Add("limit", limit)
	reqUrl += "?" + queryParams.Encode()
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return GetUsersWhereResponse{}, err
	}
	defer resp.Body.Close()
	var response GetUsersWhereResponse
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return GetUsersWhereResponse{}, err
	}
	return response, nil
}

/*
PostBlockUser makes a POST request to /api/block_user
ID: POST /api/block_user
Description: For blocking a user. Only accessible to approved OAuth applications
*/
func (sdk *ReddiGoSDK) PostBlockUser(accountId string, apiType string, name interface{}) (any, error) {
	reqUrl := "/api/block_user"
	payload := map[string]interface{}{
		"account_id": accountId,
		"api_type":   apiType,
		"name":       name,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

type PostRSubredditFriendTypeEnum string

const (
	PostRSubredditFriendTypeEnumFriend           PostRSubredditFriendTypeEnum = "friend"
	PostRSubredditFriendTypeEnumModerator        PostRSubredditFriendTypeEnum = "moderator"
	PostRSubredditFriendTypeEnumModerator_invite PostRSubredditFriendTypeEnum = "moderator_invite"
	PostRSubredditFriendTypeEnumContributor      PostRSubredditFriendTypeEnum = "contributor"
	PostRSubredditFriendTypeEnumBanned           PostRSubredditFriendTypeEnum = "banned"
	PostRSubredditFriendTypeEnumMuted            PostRSubredditFriendTypeEnum = "muted"
	PostRSubredditFriendTypeEnumWikibanned       PostRSubredditFriendTypeEnum = "wikibanned"
	PostRSubredditFriendTypeEnumWikicontributor  PostRSubredditFriendTypeEnum = "wikicontributor"
)

/*
PostRSubredditFriend makes a POST request to /r/{subreddit}/api/friend
ID: POST /r/{subreddit}/api/friend
Description: Create a relationship between a user and another user or subredditOAuth2 use requires appropriate scope based
on the 'type' of the relationship:Complement to POST_unfriend
*/
func (sdk *ReddiGoSDK) PostRSubredditFriend(subreddit string, apiType string, banContext string, banMessage interface{}, banReason string, container interface{}, duration int, name interface{}, note string, permissions interface{}, typeValue string) (any, error) {
	reqUrl := fmt.Sprintf("/r/%s/api/friend", subreddit)
	payload := map[string]interface{}{
		"api_type":    apiType,
		"ban_context": banContext,
		"ban_message": banMessage,
		"ban_reason":  banReason,
		"container":   container,
		"duration":    duration,
		"name":        name,
		"note":        note,
		"permissions": permissions,
		"type":        typeValue,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostReportUser makes a POST request to /api/report_user
ID: POST /api/report_user
Description: Report a user.
Reporting a user brings it to the attention of a Reddit admin.
*/
func (sdk *ReddiGoSDK) PostReportUser(details interface{}, reason string, user interface{}) (any, error) {
	reqUrl := "/api/report_user"
	payload := map[string]interface{}{
		"details": details,
		"reason":  reason,
		"user":    user,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostRSubredditSetpermissions makes a POST request to /r/{subreddit}/api/setpermissions
ID: POST /r/{subreddit}/api/setpermissions
Description: No description available
*/
func (sdk *ReddiGoSDK) PostRSubredditSetpermissions(subreddit string, apiType string, name interface{}, permissions interface{}, typeValue interface{}) (any, error) {
	reqUrl := fmt.Sprintf("/r/%s/api/setpermissions", subreddit)
	payload := map[string]interface{}{
		"api_type":    apiType,
		"name":        name,
		"permissions": permissions,
		"type":        typeValue,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

type PostRSubredditUnfriendTypeEnum string

const (
	PostRSubredditUnfriendTypeEnumFriend           PostRSubredditUnfriendTypeEnum = "friend"
	PostRSubredditUnfriendTypeEnumEnemy            PostRSubredditUnfriendTypeEnum = "enemy"
	PostRSubredditUnfriendTypeEnumModerator        PostRSubredditUnfriendTypeEnum = "moderator"
	PostRSubredditUnfriendTypeEnumModerator_invite PostRSubredditUnfriendTypeEnum = "moderator_invite"
	PostRSubredditUnfriendTypeEnumContributor      PostRSubredditUnfriendTypeEnum = "contributor"
	PostRSubredditUnfriendTypeEnumBanned           PostRSubredditUnfriendTypeEnum = "banned"
	PostRSubredditUnfriendTypeEnumMuted            PostRSubredditUnfriendTypeEnum = "muted"
	PostRSubredditUnfriendTypeEnumWikibanned       PostRSubredditUnfriendTypeEnum = "wikibanned"
	PostRSubredditUnfriendTypeEnumWikicontributor  PostRSubredditUnfriendTypeEnum = "wikicontributor"
)

/*
PostRSubredditUnfriend makes a POST request to /r/{subreddit}/api/unfriend
ID: POST /r/{subreddit}/api/unfriend
Description: Remove a relationship between a user and another user or subredditThe user can either be passed in by name (nuser)
or by fullname (iuser).  If type is friend or enemy,
'container' MUST be the current user's fullname;
for other types, the subreddit must be set
via URL (e.g., /r/funny/api/unfriend)OAuth2 use requires appropriate scope based
on the 'type' of the relationship:Complement to POST_friend
*/
func (sdk *ReddiGoSDK) PostRSubredditUnfriend(subreddit string, apiType string, container interface{}, id string, name interface{}, typeValue string) (any, error) {
	reqUrl := fmt.Sprintf("/r/%s/api/unfriend", subreddit)
	payload := map[string]interface{}{
		"api_type":  apiType,
		"container": container,
		"id":        id,
		"name":      name,
		"type":      typeValue,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

// GetUserDataByAccountIdsResponse represents the response for GET /api/user_data_by_account_ids
type GetUserDataByAccountIdsResponse struct {
	Ids string `json:"ids"` // A comma-separated list of account fullnames
}

/*
GetUserDataByAccountIds makes a GET request to /api/user_data_by_account_ids
ID: GET /api/user_data_by_account_ids
Description: No description available
*/
func (sdk *ReddiGoSDK) GetUserDataByAccountIds() (GetUserDataByAccountIdsResponse, error) {
	reqUrl := "/api/user_data_by_account_ids"
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return GetUserDataByAccountIdsResponse{}, err
	}
	defer resp.Body.Close()
	var response GetUserDataByAccountIdsResponse
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return GetUserDataByAccountIdsResponse{}, err
	}
	return response, nil
}

// GetUsernameAvailableResponse represents the response for GET /api/username_available
type GetUsernameAvailableResponse struct {
	User interface{} `json:"user"` // a valid, unused, username
}

/*
GetUsernameAvailable makes a GET request to /api/username_available
ID: GET /api/username_available
Description: Check whether a username is available for registration.
*/
func (sdk *ReddiGoSDK) GetUsernameAvailable() (GetUsernameAvailableResponse, error) {
	reqUrl := "/api/username_available"
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return GetUsernameAvailableResponse{}, err
	}
	defer resp.Body.Close()
	var response GetUsernameAvailableResponse
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return GetUsernameAvailableResponse{}, err
	}
	return response, nil
}

// DeleteMeFriendsUsernameResponse represents the response for DELETE /api/v1/me/friends/{username}
type DeleteMeFriendsUsernameResponse struct {
	Id interface{} `json:"id"` // A valid, existing reddit username
}

/*
DeleteMeFriendsUsername makes a DELETE request to /api/v1/me/friends/{username}
ID: DELETE /api/v1/me/friends/{username}
Description: Stop being friends with a user.
*/
func (sdk *ReddiGoSDK) DeleteMeFriendsUsername(username string) (DeleteMeFriendsUsernameResponse, error) {
	reqUrl := fmt.Sprintf("/api/v1/me/friends/%s", username)
	// Construct the request for DELETE method
	resp, err := sdk.MakeRequest("DELETE", reqUrl, nil)
	if err != nil {
		return DeleteMeFriendsUsernameResponse{}, err
	}
	defer resp.Body.Close()
	var response DeleteMeFriendsUsernameResponse
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return DeleteMeFriendsUsernameResponse{}, err
	}
	return response, nil
}

// GetMeFriendsUsernameResponse represents the response for GET /api/v1/me/friends/{username}
type GetMeFriendsUsernameResponse struct {
	Id interface{} `json:"id"` // A valid, existing reddit username
}

/*
GetMeFriendsUsername makes a GET request to /api/v1/me/friends/{username}
ID: GET /api/v1/me/friends/{username}
Description: Get information about a specific 'friend', such as notes.
*/
func (sdk *ReddiGoSDK) GetMeFriendsUsername(username string) (GetMeFriendsUsernameResponse, error) {
	reqUrl := fmt.Sprintf("/api/v1/me/friends/%s", username)
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return GetMeFriendsUsernameResponse{}, err
	}
	defer resp.Body.Close()
	var response GetMeFriendsUsernameResponse
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return GetMeFriendsUsernameResponse{}, err
	}
	return response, nil
}

/*
PutMeFriendsUsername makes a PUT request to /api/v1/me/friends/{username}
ID: PUT /api/v1/me/friends/{username}
Description: Create or update a "friend" relationship.This operation is idempotent. It can be used to add a new
friend, or update an existing friend (e.g., add/change the
note on that friend)
*/
func (sdk *ReddiGoSDK) PutMeFriendsUsername(username string, name interface{}, note string) (any, error) {
	reqUrl := fmt.Sprintf("/api/v1/me/friends/%s", username)
	payload := map[string]interface{}{
		"name": name,
		"note": note,
	}
	// Construct the request for PUT method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("PUT", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

// GetUserUsernameTrophiesResponse represents the response for GET /api/v1/user/{username}/trophies
type GetUserUsernameTrophiesResponse struct {
	Id interface{} `json:"id"` // A valid, existing reddit username
}

/*
GetUserUsernameTrophies makes a GET request to /api/v1/user/{username}/trophies
ID: GET /api/v1/user/{username}/trophies
Description: Return a list of trophies for the a given user.
*/
func (sdk *ReddiGoSDK) GetUserUsernameTrophies(username string) (GetUserUsernameTrophiesResponse, error) {
	reqUrl := fmt.Sprintf("/api/v1/user/%s/trophies", username)
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return GetUserUsernameTrophiesResponse{}, err
	}
	defer resp.Body.Close()
	var response GetUserUsernameTrophiesResponse
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return GetUserUsernameTrophiesResponse{}, err
	}
	return response, nil
}

// GetUserUsernameAboutResponse represents the response for GET /user/{username}/about
type GetUserUsernameAboutResponse struct {
	Username interface{} `json:"username"` // the name of an existing user
}

/*
GetUserUsernameAbout makes a GET request to /user/{username}/about
ID: GET /user/{username}/about
Description: Return information about the user, including karma and gold status.
*/
func (sdk *ReddiGoSDK) GetUserUsernameAbout(username string) (GetUserUsernameAboutResponse, error) {
	reqUrl := fmt.Sprintf("/user/%s/about", username)
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return GetUserUsernameAboutResponse{}, err
	}
	defer resp.Body.Close()
	var response GetUserUsernameAboutResponse
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return GetUserUsernameAboutResponse{}, err
	}
	return response, nil
}

type GetUserUsernameWhereShowEnum string

const (
	GetUserUsernameWhereShowEnumGiven GetUserUsernameWhereShowEnum = "given"
)

type GetUserUsernameWhereSortEnum string

const (
	GetUserUsernameWhereSortEnumHot           GetUserUsernameWhereSortEnum = "hot"
	GetUserUsernameWhereSortEnumNew           GetUserUsernameWhereSortEnum = "new"
	GetUserUsernameWhereSortEnumTop           GetUserUsernameWhereSortEnum = "top"
	GetUserUsernameWhereSortEnumControversial GetUserUsernameWhereSortEnum = "controversial"
)

type GetUserUsernameWhereTEnum string

const (
	GetUserUsernameWhereTEnumHour  GetUserUsernameWhereTEnum = "hour"
	GetUserUsernameWhereTEnumDay   GetUserUsernameWhereTEnum = "day"
	GetUserUsernameWhereTEnumWeek  GetUserUsernameWhereTEnum = "week"
	GetUserUsernameWhereTEnumMonth GetUserUsernameWhereTEnum = "month"
	GetUserUsernameWhereTEnumYear  GetUserUsernameWhereTEnum = "year"
	GetUserUsernameWhereTEnumAll   GetUserUsernameWhereTEnum = "all"
)

type GetUserUsernameWhereTypeEnum string

const (
	GetUserUsernameWhereTypeEnumLinks    GetUserUsernameWhereTypeEnum = "links"
	GetUserUsernameWhereTypeEnumComments GetUserUsernameWhereTypeEnum = "comments"
)

// GetUserUsernameWhereResponse represents the response for GET /user/{username}/{where}
type GetUserUsernameWhereResponse struct {
	Context   int         `json:"context"`   // an integer between 2 and 10
	Show      string      `json:"show"`      // one of (given)
	Sort      string      `json:"sort"`      // one of (hot, new, top, controversial)
	T         string      `json:"t"`         // one of (hour, day, week, month, year, all)
	TypeValue string      `json:"type"`      // one of (links, comments)
	Username  interface{} `json:"username"`  // the name of an existing user
	After     string      `json:"after"`     // fullname of a thing
	Before    string      `json:"before"`    // fullname of a thing
	Count     int         `json:"count"`     // a positive integer (default: 0)
	Limit     interface{} `json:"limit"`     // the maximum number of items desired (default: 25, maximum: 100)
	SrDetail  bool        `json:"sr_detail"` // (optional) expand subreddits
}

/*
GetUserUsernameWhere makes a GET request to /user/{username}/{where}
ID: GET /user/{username}/{where}
Description: This endpoint is a listing.
*/
func (sdk *ReddiGoSDK) GetUserUsernameWhere(username string, where string, after string, before string, count string, limit string) (GetUserUsernameWhereResponse, error) {
	reqUrl := fmt.Sprintf("/user/%s/%s", username, where)
	queryParams := urlpkg.Values{}
	queryParams.Add("after", after)
	queryParams.Add("before", before)
	queryParams.Add("count", count)
	queryParams.Add("limit", limit)
	reqUrl += "?" + queryParams.Encode()
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return GetUserUsernameWhereResponse{}, err
	}
	defer resp.Body.Close()
	var response GetUserUsernameWhereResponse
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return GetUserUsernameWhereResponse{}, err
	}
	return response, nil
}

/*
PostRSubredditWidget makes a POST request to /r/{subreddit}/api/widget
ID: POST /r/{subreddit}/api/widget
Description: Add and return a widget to the specified subredditAccepts a JSON payload representing the widget data to be saved.
Valid payloads differ in shape based on the "kind" attribute passed on
the root object, which must be a valid widget kind.
*/
func (sdk *ReddiGoSDK) PostRSubredditWidget(subreddit string, json interface{}) (any, error) {
	reqUrl := fmt.Sprintf("/r/%s/api/widget", subreddit)
	payload := json
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

// DeleteRSubredditWidgetWidgetIdResponse represents the response for DELETE /r/{subreddit}/api/widget/{widget_id}
type DeleteRSubredditWidgetWidgetIdResponse struct {
	WidgetId interface{} `json:"widget_id"` // id of an existing widget
}

/*
DeleteRSubredditWidgetWidgetId makes a DELETE request to /r/{subreddit}/api/widget/{widget_id}
ID: DELETE /r/{subreddit}/api/widget/{widget_id}
Description: Delete a widget from the specified subreddit (if it exists)
*/
func (sdk *ReddiGoSDK) DeleteRSubredditWidgetWidgetId(subreddit string, widgetId string) (DeleteRSubredditWidgetWidgetIdResponse, error) {
	reqUrl := fmt.Sprintf("/r/%s/api/widget/%s", subreddit, widgetId)
	// Construct the request for DELETE method
	resp, err := sdk.MakeRequest("DELETE", reqUrl, nil)
	if err != nil {
		return DeleteRSubredditWidgetWidgetIdResponse{}, err
	}
	defer resp.Body.Close()
	var response DeleteRSubredditWidgetWidgetIdResponse
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return DeleteRSubredditWidgetWidgetIdResponse{}, err
	}
	return response, nil
}

/*
PutRSubredditWidgetWidgetId makes a PUT request to /r/{subreddit}/api/widget/{widget_id}
ID: PUT /r/{subreddit}/api/widget/{widget_id}
Description: Update and return the data of a widget.Accepts a JSON payload representing the widget data to be saved.
Valid payloads differ in shape based on the "kind" attribute passed on
the root object, which must be a valid widget kind.
*/
func (sdk *ReddiGoSDK) PutRSubredditWidgetWidgetId(subreddit string, widgetId string, json interface{}) (any, error) {
	reqUrl := fmt.Sprintf("/r/%s/api/widget/%s", subreddit, widgetId)
	payload := map[string]interface{}{
		"json":      json,
		"widget_id": widgetId,
	}
	// Construct the request for PUT method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("PUT", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostRSubredditWidgetImageUploadS3 makes a POST request to /r/{subreddit}/api/widget_image_upload_s3
ID: POST /r/{subreddit}/api/widget_image_upload_s3
Description: Acquire and return an upload lease to s3 temp bucket.The return value of this function is a json object containing
credentials for uploading assets to S3 bucket, S3 url for upload
request and the key to use for uploading. Using this lease the client
will upload the emoji image to S3 temp bucket (included as part of
the S3 URL).This lease is used by S3 to verify that the upload is authorized.
*/
func (sdk *ReddiGoSDK) PostRSubredditWidgetImageUploadS3(subreddit string, filepath interface{}, mimetype interface{}) (any, error) {
	reqUrl := fmt.Sprintf("/r/%s/api/widget_image_upload_s3", subreddit)
	payload := map[string]interface{}{
		"filepath": filepath,
		"mimetype": mimetype,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

type PatchRSubredditWidgetOrderSectionSectionEnum string

const (
	PatchRSubredditWidgetOrderSectionSectionEnumSidebar PatchRSubredditWidgetOrderSectionSectionEnum = "sidebar"
)

/*
PatchRSubredditWidgetOrderSection makes a PATCH request to /r/{subreddit}/api/widget_order/{section}
ID: PATCH /r/{subreddit}/api/widget_order/{section}
Description: Update the order of widget_ids in the specified subreddit
*/
func (sdk *ReddiGoSDK) PatchRSubredditWidgetOrderSection(subreddit string, section string, json interface{}) (any, error) {
	reqUrl := fmt.Sprintf("/r/%s/api/widget_order/%s", subreddit, section)
	payload := map[string]interface{}{
		"json":    json,
		"section": section,
	}
	// Construct the request for PATCH method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("PATCH", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

// GetRSubredditWidgetsResponse represents the response for GET /r/{subreddit}/api/widgets
type GetRSubredditWidgetsResponse struct {
	ProgressiveImages bool `json:"progressive_images"` // boolean value
}

/*
GetRSubredditWidgets makes a GET request to /r/{subreddit}/api/widgets
ID: GET /r/{subreddit}/api/widgets
Description: Return all widgets for the given subreddit
*/
func (sdk *ReddiGoSDK) GetRSubredditWidgets(subreddit string) (GetRSubredditWidgetsResponse, error) {
	reqUrl := fmt.Sprintf("/r/%s/api/widgets", subreddit)
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return GetRSubredditWidgetsResponse{}, err
	}
	defer resp.Body.Close()
	var response GetRSubredditWidgetsResponse
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return GetRSubredditWidgetsResponse{}, err
	}
	return response, nil
}

type PostRSubredditWikiAlloweditorActActEnum string

const (
	PostRSubredditWikiAlloweditorActActEnumDel PostRSubredditWikiAlloweditorActActEnum = "del"
	PostRSubredditWikiAlloweditorActActEnumAdd PostRSubredditWikiAlloweditorActActEnum = "add"
)

/*
PostRSubredditWikiAlloweditorAct makes a POST request to /r/{subreddit}/api/wiki/alloweditor/{act}
ID: POST /r/{subreddit}/api/wiki/alloweditor/{act}
Description: Allow/deny username to edit this wiki page
*/
func (sdk *ReddiGoSDK) PostRSubredditWikiAlloweditorAct(subreddit string, act string, page interface{}, username interface{}) (any, error) {
	reqUrl := fmt.Sprintf("/r/%s/api/wiki/alloweditor/%s", subreddit, act)
	payload := map[string]interface{}{
		"act":      act,
		"page":     page,
		"username": username,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostRSubredditWikiEdit makes a POST request to /r/{subreddit}/api/wiki/edit
ID: POST /r/{subreddit}/api/wiki/edit
Description: Edit a wiki page
*/
func (sdk *ReddiGoSDK) PostRSubredditWikiEdit(subreddit string, content interface{}, page interface{}, previous interface{}, reason string) (any, error) {
	reqUrl := fmt.Sprintf("/r/%s/api/wiki/edit", subreddit)
	payload := map[string]interface{}{
		"content":  content,
		"page":     page,
		"previous": previous,
		"reason":   reason,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostRSubredditWikiHide makes a POST request to /r/{subreddit}/api/wiki/hide
ID: POST /r/{subreddit}/api/wiki/hide
Description: Toggle the public visibility of a wiki page revision
*/
func (sdk *ReddiGoSDK) PostRSubredditWikiHide(subreddit string, page interface{}, revision interface{}) (any, error) {
	reqUrl := fmt.Sprintf("/r/%s/api/wiki/hide", subreddit)
	payload := map[string]interface{}{
		"page":     page,
		"revision": revision,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostRSubredditWikiRevert makes a POST request to /r/{subreddit}/api/wiki/revert
ID: POST /r/{subreddit}/api/wiki/revert
Description: Revert a wiki page to revision
*/
func (sdk *ReddiGoSDK) PostRSubredditWikiRevert(subreddit string, page interface{}, revision interface{}) (any, error) {
	reqUrl := fmt.Sprintf("/r/%s/api/wiki/revert", subreddit)
	payload := map[string]interface{}{
		"page":     page,
		"revision": revision,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

// GetRSubredditWikiDiscussionsPageResponse represents the response for GET /r/{subreddit}/wiki/discussions/{page}
type GetRSubredditWikiDiscussionsPageResponse struct {
	After    string      `json:"after"`     // fullname of a thing
	Before   string      `json:"before"`    // fullname of a thing
	Count    int         `json:"count"`     // a positive integer (default: 0)
	Limit    interface{} `json:"limit"`     // the maximum number of items desired (default: 25, maximum: 100)
	Page     interface{} `json:"page"`      // the name of an existing wiki page
	Show     string      `json:"show"`      // (optional) the string all
	SrDetail bool        `json:"sr_detail"` // (optional) expand subreddits
}

/*
GetRSubredditWikiDiscussionsPage makes a GET request to /r/{subreddit}/wiki/discussions/{page}
ID: GET /r/{subreddit}/wiki/discussions/{page}
Description: Retrieve a list of discussions about this wiki pageThis endpoint is a listing.
*/
func (sdk *ReddiGoSDK) GetRSubredditWikiDiscussionsPage(subreddit string, page string, after string, before string, count string, limit string) (GetRSubredditWikiDiscussionsPageResponse, error) {
	reqUrl := fmt.Sprintf("/r/%s/wiki/discussions/%s", subreddit, page)
	queryParams := urlpkg.Values{}
	queryParams.Add("after", after)
	queryParams.Add("before", before)
	queryParams.Add("count", count)
	queryParams.Add("limit", limit)
	reqUrl += "?" + queryParams.Encode()
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return GetRSubredditWikiDiscussionsPageResponse{}, err
	}
	defer resp.Body.Close()
	var response GetRSubredditWikiDiscussionsPageResponse
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return GetRSubredditWikiDiscussionsPageResponse{}, err
	}
	return response, nil
}

/*
GetRSubredditWikiPages makes a GET request to /r/{subreddit}/wiki/pages
ID: GET /r/{subreddit}/wiki/pages
Description: Retrieve a list of wiki pages in this subreddit
*/
func (sdk *ReddiGoSDK) GetRSubredditWikiPages(subreddit string) (any, error) {
	reqUrl := fmt.Sprintf("/r/%s/wiki/pages", subreddit)
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

// GetRSubredditWikiRevisionsResponse represents the response for GET /r/{subreddit}/wiki/revisions
type GetRSubredditWikiRevisionsResponse struct {
	After    string      `json:"after"`     // fullname of a thing
	Before   string      `json:"before"`    // fullname of a thing
	Count    int         `json:"count"`     // a positive integer (default: 0)
	Limit    interface{} `json:"limit"`     // the maximum number of items desired (default: 25, maximum: 100)
	Show     string      `json:"show"`      // (optional) the string all
	SrDetail bool        `json:"sr_detail"` // (optional) expand subreddits
}

/*
GetRSubredditWikiRevisions makes a GET request to /r/{subreddit}/wiki/revisions
ID: GET /r/{subreddit}/wiki/revisions
Description: Retrieve a list of recently changed wiki pages in this subreddit
*/
func (sdk *ReddiGoSDK) GetRSubredditWikiRevisions(subreddit string, after string, before string, count string, limit string) (GetRSubredditWikiRevisionsResponse, error) {
	reqUrl := fmt.Sprintf("/r/%s/wiki/revisions", subreddit)
	queryParams := urlpkg.Values{}
	queryParams.Add("after", after)
	queryParams.Add("before", before)
	queryParams.Add("count", count)
	queryParams.Add("limit", limit)
	reqUrl += "?" + queryParams.Encode()
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return GetRSubredditWikiRevisionsResponse{}, err
	}
	defer resp.Body.Close()
	var response GetRSubredditWikiRevisionsResponse
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return GetRSubredditWikiRevisionsResponse{}, err
	}
	return response, nil
}

// GetRSubredditWikiRevisionsPageResponse represents the response for GET /r/{subreddit}/wiki/revisions/{page}
type GetRSubredditWikiRevisionsPageResponse struct {
	After    string      `json:"after"`     // fullname of a thing
	Before   string      `json:"before"`    // fullname of a thing
	Count    int         `json:"count"`     // a positive integer (default: 0)
	Limit    interface{} `json:"limit"`     // the maximum number of items desired (default: 25, maximum: 100)
	Page     interface{} `json:"page"`      // the name of an existing wiki page
	Show     string      `json:"show"`      // (optional) the string all
	SrDetail bool        `json:"sr_detail"` // (optional) expand subreddits
}

/*
GetRSubredditWikiRevisionsPage makes a GET request to /r/{subreddit}/wiki/revisions/{page}
ID: GET /r/{subreddit}/wiki/revisions/{page}
Description: Retrieve a list of revisions of this wiki pageThis endpoint is a listing.
*/
func (sdk *ReddiGoSDK) GetRSubredditWikiRevisionsPage(subreddit string, page string, after string, before string, count string, limit string) (GetRSubredditWikiRevisionsPageResponse, error) {
	reqUrl := fmt.Sprintf("/r/%s/wiki/revisions/%s", subreddit, page)
	queryParams := urlpkg.Values{}
	queryParams.Add("after", after)
	queryParams.Add("before", before)
	queryParams.Add("count", count)
	queryParams.Add("limit", limit)
	reqUrl += "?" + queryParams.Encode()
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return GetRSubredditWikiRevisionsPageResponse{}, err
	}
	defer resp.Body.Close()
	var response GetRSubredditWikiRevisionsPageResponse
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return GetRSubredditWikiRevisionsPageResponse{}, err
	}
	return response, nil
}

// GetRSubredditWikiSettingsPageResponse represents the response for GET /r/{subreddit}/wiki/settings/{page}
type GetRSubredditWikiSettingsPageResponse struct {
	Page interface{} `json:"page"` // the name of an existing wiki page
}

/*
GetRSubredditWikiSettingsPage makes a GET request to /r/{subreddit}/wiki/settings/{page}
ID: GET /r/{subreddit}/wiki/settings/{page}
Description: Retrieve the current permission settings for page
*/
func (sdk *ReddiGoSDK) GetRSubredditWikiSettingsPage(subreddit string, page string) (GetRSubredditWikiSettingsPageResponse, error) {
	reqUrl := fmt.Sprintf("/r/%s/wiki/settings/%s", subreddit, page)
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return GetRSubredditWikiSettingsPageResponse{}, err
	}
	defer resp.Body.Close()
	var response GetRSubredditWikiSettingsPageResponse
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return GetRSubredditWikiSettingsPageResponse{}, err
	}
	return response, nil
}

/*
PostRSubredditWikiSettingsPage makes a POST request to /r/{subreddit}/wiki/settings/{page}
ID: POST /r/{subreddit}/wiki/settings/{page}
Description: Update the permissions and visibility of wiki page
*/
func (sdk *ReddiGoSDK) PostRSubredditWikiSettingsPage(subreddit string, page string, listed bool, permlevel int) (any, error) {
	reqUrl := fmt.Sprintf("/r/%s/wiki/settings/%s", subreddit, page)
	payload := map[string]interface{}{
		"listed":    listed,
		"page":      page,
		"permlevel": permlevel,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

// GetRSubredditWikiPageResponse represents the response for GET /r/{subreddit}/wiki/{page}
type GetRSubredditWikiPageResponse struct {
	Page interface{} `json:"page"` // the name of an existing wiki page
	V    interface{} `json:"v"`    // a wiki revision ID
	V2   interface{} `json:"v2"`   // a wiki revision ID
}

/*
GetRSubredditWikiPage makes a GET request to /r/{subreddit}/wiki/{page}
ID: GET /r/{subreddit}/wiki/{page}
Description: Return the content of a wiki pageIf v is given, show the wiki page as it was at that version
If both v and v2 are given, show a diff of the two
*/
func (sdk *ReddiGoSDK) GetRSubredditWikiPage(subreddit string, page string) (GetRSubredditWikiPageResponse, error) {
	reqUrl := fmt.Sprintf("/r/%s/wiki/%s", subreddit, page)
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return GetRSubredditWikiPageResponse{}, err
	}
	defer resp.Body.Close()
	var response GetRSubredditWikiPageResponse
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return GetRSubredditWikiPageResponse{}, err
	}
	return response, nil
}

/*
PostSetSubredditSticky makes a POST request to /api/set_subreddit_sticky
ID: POST /api/set_subreddit_sticky
Description: Set or unset a Link as the sticky in its subreddit.state is a boolean that indicates whether to sticky or unsticky
this post - true to sticky, false to unsticky.The num argument is optional, and only used when stickying a post.
It allows specifying a particular "slot" to sticky the post into, and
if there is already a post stickied in that slot it will be replaced.
If there is no post in the specified slot to replace, or num is None,
the bottom-most slot will be used.
*/
func (sdk *ReddiGoSDK) PostSetSubredditSticky(apiType string, id interface{}, num int, state bool, toProfile bool) (any, error) {
	reqUrl := "/api/set_subreddit_sticky"
	payload := map[string]interface{}{
		"api_type":   apiType,
		"id":         id,
		"num":        num,
		"state":      state,
		"to_profile": toProfile,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

type PostSetSuggestedSortSortEnum string

const (
	PostSetSuggestedSortSortEnumConfidence    PostSetSuggestedSortSortEnum = "confidence"
	PostSetSuggestedSortSortEnumTop           PostSetSuggestedSortSortEnum = "top"
	PostSetSuggestedSortSortEnumNew           PostSetSuggestedSortSortEnum = "new"
	PostSetSuggestedSortSortEnumControversial PostSetSuggestedSortSortEnum = "controversial"
	PostSetSuggestedSortSortEnumOld           PostSetSuggestedSortSortEnum = "old"
	PostSetSuggestedSortSortEnumRandom        PostSetSuggestedSortSortEnum = "random"
	PostSetSuggestedSortSortEnumQa            PostSetSuggestedSortSortEnum = "qa"
	PostSetSuggestedSortSortEnumLive          PostSetSuggestedSortSortEnum = "live"
	PostSetSuggestedSortSortEnumBlank         PostSetSuggestedSortSortEnum = "blank"
)

/*
PostSetSuggestedSort makes a POST request to /api/set_suggested_sort
ID: POST /api/set_suggested_sort
Description: Set a suggested sort for a link.Suggested sorts are useful to display comments in a certain preferred way
for posts. For example, casual conversation may be better sorted by new
by default, or AMAs may be sorted by Q&A. A sort of an empty string
clears the default sort.
*/
func (sdk *ReddiGoSDK) PostSetSuggestedSort(apiType string, id interface{}, sort string) (any, error) {
	reqUrl := "/api/set_suggested_sort"
	payload := map[string]interface{}{
		"api_type": apiType,
		"id":       id,
		"sort":     sort,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostSpoiler makes a POST request to /api/spoiler
ID: POST /api/spoiler
Description: No description available
*/
func (sdk *ReddiGoSDK) PostSpoiler(id string) (any, error) {
	reqUrl := "/api/spoiler"
	payload := map[string]interface{}{
		"id": id,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostStoreVisits makes a POST request to /api/store_visits
ID: POST /api/store_visits
Description: Requires a subscription to reddit premium
*/
func (sdk *ReddiGoSDK) PostStoreVisits(links string) (any, error) {
	reqUrl := "/api/store_visits"
	payload := map[string]interface{}{
		"links": links,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

type PostSubmitKindEnum string

const (
	PostSubmitKindEnumLink     PostSubmitKindEnum = "link"
	PostSubmitKindEnumSelf     PostSubmitKindEnum = "self"
	PostSubmitKindEnumImage    PostSubmitKindEnum = "image"
	PostSubmitKindEnumVideo    PostSubmitKindEnum = "video"
	PostSubmitKindEnumVideogif PostSubmitKindEnum = "videogif"
)

/*
PostSubmit makes a POST request to /api/submit
ID: POST /api/submit
Description: Submit a link to a subreddit.Submit will create a link or self-post in the subreddit sr with the
title title. If kind is "link", then url is expected to be a
valid URL to link to. Otherwise, text, if present, will be the
body of the self-post unless richtext_json is present, in which case
it will be converted into the body of the self-post. An error is thrown
if both text and richtext_json are present.extension is used for determining which view-type (e.g. json,
compact etc.) to use for the redirect that is generated after submit.
*/
func (sdk *ReddiGoSDK) PostSubmit(ad bool, apiType string, app interface{}, collectionId interface{}, extension interface{}, flairId string, flairText string, gRecaptchaResponse interface{}, kind string, nsfw bool, postSetDefaultPostId string, postSetId string, recaptchaToken string, resubmit bool, richtextJson interface{}, sendreplies bool, spoiler bool, sr interface{}, text interface{}, title string, url string, videoPosterUrl string) (any, error) {
	reqUrl := "/api/submit"
	payload := map[string]interface{}{
		"ad":                       ad,
		"api_type":                 apiType,
		"app":                      app,
		"collection_id":            collectionId,
		"extension":                extension,
		"flair_id":                 flairId,
		"flair_text":               flairText,
		"g-recaptcha-response":     gRecaptchaResponse,
		"kind":                     kind,
		"nsfw":                     nsfw,
		"post_set_default_post_id": postSetDefaultPostId,
		"post_set_id":              postSetId,
		"recaptcha_token":          recaptchaToken,
		"resubmit":                 resubmit,
		"richtext_json":            richtextJson,
		"sendreplies":              sendreplies,
		"spoiler":                  spoiler,
		"sr":                       sr,
		"text":                     text,
		"title":                    title,
		"url":                      url,
		"video_poster_url":         videoPosterUrl,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostUnhide makes a POST request to /api/unhide
ID: POST /api/unhide
Description: Unhide a link.See also: /api/hide.
*/
func (sdk *ReddiGoSDK) PostUnhide(id string) (any, error) {
	reqUrl := "/api/unhide"
	payload := map[string]interface{}{
		"id": id,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostUnlock makes a POST request to /api/unlock
ID: POST /api/unlock
Description: Unlock a link or comment.Allow a post or comment to receive new comments.See also: /api/lock.
*/
func (sdk *ReddiGoSDK) PostUnlock(id string) (any, error) {
	reqUrl := "/api/unlock"
	payload := map[string]interface{}{
		"id": id,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostUnmarknsfw makes a POST request to /api/unmarknsfw
ID: POST /api/unmarknsfw
Description: Remove the NSFW marking from a link.See also: /api/marknsfw.
*/
func (sdk *ReddiGoSDK) PostUnmarknsfw(id string) (any, error) {
	reqUrl := "/api/unmarknsfw"
	payload := map[string]interface{}{
		"id": id,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostUnsave makes a POST request to /api/unsave
ID: POST /api/unsave
Description: Unsave a link or comment.This removes the thing from the user's saved listings as well.See also: /api/save.
*/
func (sdk *ReddiGoSDK) PostUnsave(id string) (any, error) {
	reqUrl := "/api/unsave"
	payload := map[string]interface{}{
		"id": id,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostUnspoiler makes a POST request to /api/unspoiler
ID: POST /api/unspoiler
Description: No description available
*/
func (sdk *ReddiGoSDK) PostUnspoiler(id string) (any, error) {
	reqUrl := "/api/unspoiler"
	payload := map[string]interface{}{
		"id": id,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

type PostVoteDirEnum string

const (
	PostVoteDirEnum1      PostVoteDirEnum = "1"
	PostVoteDirEnum0      PostVoteDirEnum = "0"
	PostVoteDirEnumMinus1 PostVoteDirEnum = "-1"
)

/*
PostVote makes a POST request to /api/vote
ID: POST /api/vote
Description: Cast a vote on a thing.id should be the fullname of the Link or Comment to vote on.dir indicates the direction of the vote. Voting 1 is an upvote,
-1 is a downvote, and 0 is equivalent to "un-voting" by clicking
again on a highlighted arrow.Note: votes must be cast by humans. That is, API clients proxying a
human's action one-for-one are OK, but bots deciding how to vote on
content or amplifying a human's vote are not. See the reddit
rules for more details on what constitutes vote cheating.
*/
func (sdk *ReddiGoSDK) PostVote(dir string, id string, rank int) (any, error) {
	reqUrl := "/api/vote"
	payload := map[string]interface{}{
		"dir":  dir,
		"id":   id,
		"rank": rank,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

// GetBestResponse represents the response for GET /best
type GetBestResponse struct {
	After    string      `json:"after"`     // fullname of a thing
	Before   string      `json:"before"`    // fullname of a thing
	Count    int         `json:"count"`     // a positive integer (default: 0)
	Limit    interface{} `json:"limit"`     // the maximum number of items desired (default: 25, maximum: 100)
	Show     string      `json:"show"`      // (optional) the string all
	SrDetail bool        `json:"sr_detail"` // (optional) expand subreddits
}

/*
GetBest makes a GET request to /best
ID: GET /best
Description: This endpoint is a listing.
*/
func (sdk *ReddiGoSDK) GetBest(after string, before string, count string, limit string) (GetBestResponse, error) {
	reqUrl := "/best"
	queryParams := urlpkg.Values{}
	queryParams.Add("after", after)
	queryParams.Add("before", before)
	queryParams.Add("count", count)
	queryParams.Add("limit", limit)
	reqUrl += "?" + queryParams.Encode()
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return GetBestResponse{}, err
	}
	defer resp.Body.Close()
	var response GetBestResponse
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return GetBestResponse{}, err
	}
	return response, nil
}

// GetByIdNamesResponse represents the response for GET /by_id/{names}
type GetByIdNamesResponse struct {
	Names string `json:"names"` // A comma-separated list of link fullnames
}

/*
GetByIdNames makes a GET request to /by_id/{names}
ID: GET /by_id/{names}
Description: Get a listing of links by fullname.names is a list of fullnames for links separated by commas or spaces.
*/
func (sdk *ReddiGoSDK) GetByIdNames(names string) (GetByIdNamesResponse, error) {
	reqUrl := fmt.Sprintf("/by_id/%s", names)
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return GetByIdNamesResponse{}, err
	}
	defer resp.Body.Close()
	var response GetByIdNamesResponse
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return GetByIdNamesResponse{}, err
	}
	return response, nil
}

type GetRSubredditCommentsArticleSortEnum string

const (
	GetRSubredditCommentsArticleSortEnumConfidence    GetRSubredditCommentsArticleSortEnum = "confidence"
	GetRSubredditCommentsArticleSortEnumTop           GetRSubredditCommentsArticleSortEnum = "top"
	GetRSubredditCommentsArticleSortEnumNew           GetRSubredditCommentsArticleSortEnum = "new"
	GetRSubredditCommentsArticleSortEnumControversial GetRSubredditCommentsArticleSortEnum = "controversial"
	GetRSubredditCommentsArticleSortEnumOld           GetRSubredditCommentsArticleSortEnum = "old"
	GetRSubredditCommentsArticleSortEnumRandom        GetRSubredditCommentsArticleSortEnum = "random"
	GetRSubredditCommentsArticleSortEnumQa            GetRSubredditCommentsArticleSortEnum = "qa"
	GetRSubredditCommentsArticleSortEnumLive          GetRSubredditCommentsArticleSortEnum = "live"
)

type GetRSubredditCommentsArticleThemeEnum string

const (
	GetRSubredditCommentsArticleThemeEnumDefault GetRSubredditCommentsArticleThemeEnum = "default"
	GetRSubredditCommentsArticleThemeEnumDark    GetRSubredditCommentsArticleThemeEnum = "dark"
)

// GetRSubredditCommentsArticleResponse represents the response for GET /r/{subreddit}/comments/{article}
type GetRSubredditCommentsArticleResponse struct {
	Article   interface{} `json:"article"`   // ID36 of a link
	Comment   interface{} `json:"comment"`   // (optional) ID36 of a comment
	Context   int         `json:"context"`   // an integer between 0 and 8
	Depth     int         `json:"depth"`     // (optional) an integer
	Limit     int         `json:"limit"`     // (optional) an integer
	Showedits bool        `json:"showedits"` // boolean value
	Showmedia bool        `json:"showmedia"` // boolean value
	Showmore  bool        `json:"showmore"`  // boolean value
	Showtitle bool        `json:"showtitle"` // boolean value
	Sort      string      `json:"sort"`      // one of (confidence, top, new, controversial, old, random, qa, live)
	SrDetail  bool        `json:"sr_detail"` // (optional) expand subreddits
	Theme     string      `json:"theme"`     // one of (default, dark)
	Threaded  bool        `json:"threaded"`  // boolean value
	Truncate  int         `json:"truncate"`  // an integer between 0 and 50
}

/*
GetRSubredditCommentsArticle makes a GET request to /r/{subreddit}/comments/{article}
ID: GET /r/{subreddit}/comments/{article}
Description: Get the comment tree for a given Link article.If supplied, comment is the ID36 of a comment in the comment tree for
article. This comment will be the (highlighted) focal point of the
returned view and context will be the number of parents shown.depth is the maximum depth of subtrees in the thread.limit is the maximum number of comments to return.See also: /api/morechildren and
/api/comment.
*/
func (sdk *ReddiGoSDK) GetRSubredditCommentsArticle(subreddit string, article string, limit string) (GetRSubredditCommentsArticleResponse, error) {
	reqUrl := fmt.Sprintf("/r/%s/comments/%s", subreddit, article)
	queryParams := urlpkg.Values{}
	queryParams.Add("limit", limit)
	reqUrl += "?" + queryParams.Encode()
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return GetRSubredditCommentsArticleResponse{}, err
	}
	defer resp.Body.Close()
	var response GetRSubredditCommentsArticleResponse
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return GetRSubredditCommentsArticleResponse{}, err
	}
	return response, nil
}

type GetDuplicatesArticleSortEnum string

const (
	GetDuplicatesArticleSortEnumNum_comments GetDuplicatesArticleSortEnum = "num_comments"
	GetDuplicatesArticleSortEnumNew          GetDuplicatesArticleSortEnum = "new"
)

// GetDuplicatesArticleResponse represents the response for GET /duplicates/{article}
type GetDuplicatesArticleResponse struct {
	After          string      `json:"after"`           // fullname of a thing
	Article        interface{} `json:"article"`         // The base 36 ID of a Link
	Before         string      `json:"before"`          // fullname of a thing
	Count          int         `json:"count"`           // a positive integer (default: 0)
	CrosspostsOnly bool        `json:"crossposts_only"` // boolean value
	Limit          interface{} `json:"limit"`           // the maximum number of items desired (default: 25, maximum: 100)
	Show           string      `json:"show"`            // (optional) the string all
	Sort           string      `json:"sort"`            // one of (num_comments, new)
	Sr             interface{} `json:"sr"`              // subreddit name
	SrDetail       bool        `json:"sr_detail"`       // (optional) expand subreddits
}

/*
GetDuplicatesArticle makes a GET request to /duplicates/{article}
ID: GET /duplicates/{article}
Description: Return a list of other submissions of the same URLThis endpoint is a listing.
*/
func (sdk *ReddiGoSDK) GetDuplicatesArticle(article string, after string, before string, count string, limit string) (GetDuplicatesArticleResponse, error) {
	reqUrl := fmt.Sprintf("/duplicates/%s", article)
	queryParams := urlpkg.Values{}
	queryParams.Add("after", after)
	queryParams.Add("before", before)
	queryParams.Add("count", count)
	queryParams.Add("limit", limit)
	reqUrl += "?" + queryParams.Encode()
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return GetDuplicatesArticleResponse{}, err
	}
	defer resp.Body.Close()
	var response GetDuplicatesArticleResponse
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return GetDuplicatesArticleResponse{}, err
	}
	return response, nil
}

type GetRSubredditHotGEnum string

const (
	GetRSubredditHotGEnumGLOBAL GetRSubredditHotGEnum = "GLOBAL"
	GetRSubredditHotGEnumUS     GetRSubredditHotGEnum = "US"
	GetRSubredditHotGEnumAR     GetRSubredditHotGEnum = "AR"
	GetRSubredditHotGEnumAU     GetRSubredditHotGEnum = "AU"
	GetRSubredditHotGEnumBG     GetRSubredditHotGEnum = "BG"
	GetRSubredditHotGEnumCA     GetRSubredditHotGEnum = "CA"
	GetRSubredditHotGEnumCL     GetRSubredditHotGEnum = "CL"
	GetRSubredditHotGEnumCO     GetRSubredditHotGEnum = "CO"
	GetRSubredditHotGEnumHR     GetRSubredditHotGEnum = "HR"
	GetRSubredditHotGEnumCZ     GetRSubredditHotGEnum = "CZ"
	GetRSubredditHotGEnumFI     GetRSubredditHotGEnum = "FI"
	GetRSubredditHotGEnumFR     GetRSubredditHotGEnum = "FR"
	GetRSubredditHotGEnumDE     GetRSubredditHotGEnum = "DE"
	GetRSubredditHotGEnumGR     GetRSubredditHotGEnum = "GR"
	GetRSubredditHotGEnumHU     GetRSubredditHotGEnum = "HU"
	GetRSubredditHotGEnumIS     GetRSubredditHotGEnum = "IS"
	GetRSubredditHotGEnumIN     GetRSubredditHotGEnum = "IN"
	GetRSubredditHotGEnumIE     GetRSubredditHotGEnum = "IE"
	GetRSubredditHotGEnumIT     GetRSubredditHotGEnum = "IT"
	GetRSubredditHotGEnumJP     GetRSubredditHotGEnum = "JP"
	GetRSubredditHotGEnumMY     GetRSubredditHotGEnum = "MY"
	GetRSubredditHotGEnumMX     GetRSubredditHotGEnum = "MX"
	GetRSubredditHotGEnumNZ     GetRSubredditHotGEnum = "NZ"
	GetRSubredditHotGEnumPH     GetRSubredditHotGEnum = "PH"
	GetRSubredditHotGEnumPL     GetRSubredditHotGEnum = "PL"
	GetRSubredditHotGEnumPT     GetRSubredditHotGEnum = "PT"
	GetRSubredditHotGEnumPR     GetRSubredditHotGEnum = "PR"
	GetRSubredditHotGEnumRO     GetRSubredditHotGEnum = "RO"
	GetRSubredditHotGEnumRS     GetRSubredditHotGEnum = "RS"
	GetRSubredditHotGEnumSG     GetRSubredditHotGEnum = "SG"
	GetRSubredditHotGEnumES     GetRSubredditHotGEnum = "ES"
	GetRSubredditHotGEnumSE     GetRSubredditHotGEnum = "SE"
	GetRSubredditHotGEnumTW     GetRSubredditHotGEnum = "TW"
	GetRSubredditHotGEnumTH     GetRSubredditHotGEnum = "TH"
	GetRSubredditHotGEnumTR     GetRSubredditHotGEnum = "TR"
	GetRSubredditHotGEnumGB     GetRSubredditHotGEnum = "GB"
	GetRSubredditHotGEnumUS_WA  GetRSubredditHotGEnum = "US_WA"
	GetRSubredditHotGEnumUS_DE  GetRSubredditHotGEnum = "US_DE"
	GetRSubredditHotGEnumUS_DC  GetRSubredditHotGEnum = "US_DC"
	GetRSubredditHotGEnumUS_WI  GetRSubredditHotGEnum = "US_WI"
	GetRSubredditHotGEnumUS_WV  GetRSubredditHotGEnum = "US_WV"
	GetRSubredditHotGEnumUS_HI  GetRSubredditHotGEnum = "US_HI"
	GetRSubredditHotGEnumUS_FL  GetRSubredditHotGEnum = "US_FL"
	GetRSubredditHotGEnumUS_WY  GetRSubredditHotGEnum = "US_WY"
	GetRSubredditHotGEnumUS_NH  GetRSubredditHotGEnum = "US_NH"
	GetRSubredditHotGEnumUS_NJ  GetRSubredditHotGEnum = "US_NJ"
	GetRSubredditHotGEnumUS_NM  GetRSubredditHotGEnum = "US_NM"
	GetRSubredditHotGEnumUS_TX  GetRSubredditHotGEnum = "US_TX"
	GetRSubredditHotGEnumUS_LA  GetRSubredditHotGEnum = "US_LA"
	GetRSubredditHotGEnumUS_NC  GetRSubredditHotGEnum = "US_NC"
	GetRSubredditHotGEnumUS_ND  GetRSubredditHotGEnum = "US_ND"
	GetRSubredditHotGEnumUS_NE  GetRSubredditHotGEnum = "US_NE"
	GetRSubredditHotGEnumUS_TN  GetRSubredditHotGEnum = "US_TN"
	GetRSubredditHotGEnumUS_NY  GetRSubredditHotGEnum = "US_NY"
	GetRSubredditHotGEnumUS_PA  GetRSubredditHotGEnum = "US_PA"
	GetRSubredditHotGEnumUS_CA  GetRSubredditHotGEnum = "US_CA"
	GetRSubredditHotGEnumUS_NV  GetRSubredditHotGEnum = "US_NV"
	GetRSubredditHotGEnumUS_VA  GetRSubredditHotGEnum = "US_VA"
	GetRSubredditHotGEnumUS_CO  GetRSubredditHotGEnum = "US_CO"
	GetRSubredditHotGEnumUS_AK  GetRSubredditHotGEnum = "US_AK"
	GetRSubredditHotGEnumUS_AL  GetRSubredditHotGEnum = "US_AL"
	GetRSubredditHotGEnumUS_AR  GetRSubredditHotGEnum = "US_AR"
	GetRSubredditHotGEnumUS_VT  GetRSubredditHotGEnum = "US_VT"
	GetRSubredditHotGEnumUS_IL  GetRSubredditHotGEnum = "US_IL"
	GetRSubredditHotGEnumUS_GA  GetRSubredditHotGEnum = "US_GA"
	GetRSubredditHotGEnumUS_IN  GetRSubredditHotGEnum = "US_IN"
	GetRSubredditHotGEnumUS_IA  GetRSubredditHotGEnum = "US_IA"
	GetRSubredditHotGEnumUS_OK  GetRSubredditHotGEnum = "US_OK"
	GetRSubredditHotGEnumUS_AZ  GetRSubredditHotGEnum = "US_AZ"
	GetRSubredditHotGEnumUS_ID  GetRSubredditHotGEnum = "US_ID"
	GetRSubredditHotGEnumUS_CT  GetRSubredditHotGEnum = "US_CT"
	GetRSubredditHotGEnumUS_ME  GetRSubredditHotGEnum = "US_ME"
	GetRSubredditHotGEnumUS_MD  GetRSubredditHotGEnum = "US_MD"
	GetRSubredditHotGEnumUS_MA  GetRSubredditHotGEnum = "US_MA"
	GetRSubredditHotGEnumUS_OH  GetRSubredditHotGEnum = "US_OH"
	GetRSubredditHotGEnumUS_UT  GetRSubredditHotGEnum = "US_UT"
	GetRSubredditHotGEnumUS_MO  GetRSubredditHotGEnum = "US_MO"
	GetRSubredditHotGEnumUS_MN  GetRSubredditHotGEnum = "US_MN"
	GetRSubredditHotGEnumUS_MI  GetRSubredditHotGEnum = "US_MI"
	GetRSubredditHotGEnumUS_RI  GetRSubredditHotGEnum = "US_RI"
	GetRSubredditHotGEnumUS_KS  GetRSubredditHotGEnum = "US_KS"
	GetRSubredditHotGEnumUS_MT  GetRSubredditHotGEnum = "US_MT"
	GetRSubredditHotGEnumUS_MS  GetRSubredditHotGEnum = "US_MS"
	GetRSubredditHotGEnumUS_SC  GetRSubredditHotGEnum = "US_SC"
	GetRSubredditHotGEnumUS_KY  GetRSubredditHotGEnum = "US_KY"
	GetRSubredditHotGEnumUS_OR  GetRSubredditHotGEnum = "US_OR"
	GetRSubredditHotGEnumUS_SD  GetRSubredditHotGEnum = "US_SD"
)

// GetRSubredditHotResponse represents the response for GET /r/{subreddit}/hot
type GetRSubredditHotResponse struct {
	G        string      `json:"g"`         // one of (GLOBAL, US, AR, AU, BG, CA, CL, CO, HR, CZ, FI, FR, DE, GR, HU, IS, IN, IE, IT, JP, MY, MX, NZ, PH, PL, PT, PR, RO, RS, SG, ES, SE, TW, TH, TR, GB, US_WA, US_DE, US_DC, US_WI, US_WV, US_HI, US_FL, US_WY, US_NH, US_NJ, US_NM, US_TX, US_LA, US_NC, US_ND, US_NE, US_TN, US_NY, US_PA, US_CA, US_NV, US_VA, US_CO, US_AK, US_AL, US_AR, US_VT, US_IL, US_GA, US_IN, US_IA, US_OK, US_AZ, US_ID, US_CT, US_ME, US_MD, US_MA, US_OH, US_UT, US_MO, US_MN, US_MI, US_RI, US_KS, US_MT, US_MS, US_SC, US_KY, US_OR, US_SD)
	After    string      `json:"after"`     // fullname of a thing
	Before   string      `json:"before"`    // fullname of a thing
	Count    int         `json:"count"`     // a positive integer (default: 0)
	Limit    interface{} `json:"limit"`     // the maximum number of items desired (default: 25, maximum: 100)
	Show     string      `json:"show"`      // (optional) the string all
	SrDetail bool        `json:"sr_detail"` // (optional) expand subreddits
}

/*
GetRSubredditHot makes a GET request to /r/{subreddit}/hot
ID: GET /r/{subreddit}/hot
Description: This endpoint is a listing.
*/
func (sdk *ReddiGoSDK) GetRSubredditHot(subreddit string, after string, before string, count string, limit string) (GetRSubredditHotResponse, error) {
	reqUrl := fmt.Sprintf("/r/%s/hot", subreddit)
	queryParams := urlpkg.Values{}
	queryParams.Add("after", after)
	queryParams.Add("before", before)
	queryParams.Add("count", count)
	queryParams.Add("limit", limit)
	reqUrl += "?" + queryParams.Encode()
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return GetRSubredditHotResponse{}, err
	}
	defer resp.Body.Close()
	var response GetRSubredditHotResponse
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return GetRSubredditHotResponse{}, err
	}
	return response, nil
}

// GetRSubredditNewResponse represents the response for GET /r/{subreddit}/new
type GetRSubredditNewResponse struct {
	After    string      `json:"after"`     // fullname of a thing
	Before   string      `json:"before"`    // fullname of a thing
	Count    int         `json:"count"`     // a positive integer (default: 0)
	Limit    interface{} `json:"limit"`     // the maximum number of items desired (default: 25, maximum: 100)
	Show     string      `json:"show"`      // (optional) the string all
	SrDetail bool        `json:"sr_detail"` // (optional) expand subreddits
}

/*
GetRSubredditNew makes a GET request to /r/{subreddit}/new
ID: GET /r/{subreddit}/new
Description: This endpoint is a listing.
*/
func (sdk *ReddiGoSDK) GetRSubredditNew(subreddit string, after string, before string, count string, limit string) (GetRSubredditNewResponse, error) {
	reqUrl := fmt.Sprintf("/r/%s/new", subreddit)
	queryParams := urlpkg.Values{}
	queryParams.Add("after", after)
	queryParams.Add("before", before)
	queryParams.Add("count", count)
	queryParams.Add("limit", limit)
	reqUrl += "?" + queryParams.Encode()
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return GetRSubredditNewResponse{}, err
	}
	defer resp.Body.Close()
	var response GetRSubredditNewResponse
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return GetRSubredditNewResponse{}, err
	}
	return response, nil
}

/*
GetRSubredditRandom makes a GET request to /r/{subreddit}/random
ID: GET /r/{subreddit}/random
Description: The Serendipity button
*/
func (sdk *ReddiGoSDK) GetRSubredditRandom(subreddit string) (any, error) {
	reqUrl := fmt.Sprintf("/r/%s/random", subreddit)
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

// GetRSubredditRisingResponse represents the response for GET /r/{subreddit}/rising
type GetRSubredditRisingResponse struct {
	After    string      `json:"after"`     // fullname of a thing
	Before   string      `json:"before"`    // fullname of a thing
	Count    int         `json:"count"`     // a positive integer (default: 0)
	Limit    interface{} `json:"limit"`     // the maximum number of items desired (default: 25, maximum: 100)
	Show     string      `json:"show"`      // (optional) the string all
	SrDetail bool        `json:"sr_detail"` // (optional) expand subreddits
}

/*
GetRSubredditRising makes a GET request to /r/{subreddit}/rising
ID: GET /r/{subreddit}/rising
Description: This endpoint is a listing.
*/
func (sdk *ReddiGoSDK) GetRSubredditRising(subreddit string, after string, before string, count string, limit string) (GetRSubredditRisingResponse, error) {
	reqUrl := fmt.Sprintf("/r/%s/rising", subreddit)
	queryParams := urlpkg.Values{}
	queryParams.Add("after", after)
	queryParams.Add("before", before)
	queryParams.Add("count", count)
	queryParams.Add("limit", limit)
	reqUrl += "?" + queryParams.Encode()
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return GetRSubredditRisingResponse{}, err
	}
	defer resp.Body.Close()
	var response GetRSubredditRisingResponse
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return GetRSubredditRisingResponse{}, err
	}
	return response, nil
}

type GetRSubredditSortTEnum string

const (
	GetRSubredditSortTEnumHour  GetRSubredditSortTEnum = "hour"
	GetRSubredditSortTEnumDay   GetRSubredditSortTEnum = "day"
	GetRSubredditSortTEnumWeek  GetRSubredditSortTEnum = "week"
	GetRSubredditSortTEnumMonth GetRSubredditSortTEnum = "month"
	GetRSubredditSortTEnumYear  GetRSubredditSortTEnum = "year"
	GetRSubredditSortTEnumAll   GetRSubredditSortTEnum = "all"
)

// GetRSubredditSortResponse represents the response for GET /r/{subreddit}/{sort}
type GetRSubredditSortResponse struct {
	T        string      `json:"t"`         // one of (hour, day, week, month, year, all)
	After    string      `json:"after"`     // fullname of a thing
	Before   string      `json:"before"`    // fullname of a thing
	Count    int         `json:"count"`     // a positive integer (default: 0)
	Limit    interface{} `json:"limit"`     // the maximum number of items desired (default: 25, maximum: 100)
	Show     string      `json:"show"`      // (optional) the string all
	SrDetail bool        `json:"sr_detail"` // (optional) expand subreddits
}

/*
GetRSubredditSort makes a GET request to /r/{subreddit}/{sort}
ID: GET /r/{subreddit}/{sort}
Description: This endpoint is a listing.
*/
func (sdk *ReddiGoSDK) GetRSubredditSort(subreddit string, sort string, after string, before string, count string, limit string) (GetRSubredditSortResponse, error) {
	reqUrl := fmt.Sprintf("/r/%s/%s", subreddit, sort)
	queryParams := urlpkg.Values{}
	queryParams.Add("after", after)
	queryParams.Add("before", before)
	queryParams.Add("count", count)
	queryParams.Add("limit", limit)
	reqUrl += "?" + queryParams.Encode()
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return GetRSubredditSortResponse{}, err
	}
	defer resp.Body.Close()
	var response GetRSubredditSortResponse
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return GetRSubredditSortResponse{}, err
	}
	return response, nil
}

// GetLiveByIdNamesResponse represents the response for GET /api/live/by_id/{names}
type GetLiveByIdNamesResponse struct {
	Names string `json:"names"` // a comma-delimited list of live thread fullnames or IDs
}

/*
GetLiveByIdNames makes a GET request to /api/live/by_id/{names}
ID: GET /api/live/by_id/{names}
Description: Get a listing of live events by id.
*/
func (sdk *ReddiGoSDK) GetLiveByIdNames(names string) (GetLiveByIdNamesResponse, error) {
	reqUrl := fmt.Sprintf("/api/live/by_id/%s", names)
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return GetLiveByIdNamesResponse{}, err
	}
	defer resp.Body.Close()
	var response GetLiveByIdNamesResponse
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return GetLiveByIdNamesResponse{}, err
	}
	return response, nil
}

/*
PostLiveCreate makes a POST request to /api/live/create
ID: POST /api/live/create
Description: Create a new live thread.Once created, the initial settings can be modified with
/api/live/thread/edit and new updates
can be posted with
/api/live/thread/update.
*/
func (sdk *ReddiGoSDK) PostLiveCreate(apiType string, description interface{}, nsfw bool, resources interface{}, title string) (any, error) {
	reqUrl := "/api/live/create"
	payload := map[string]interface{}{
		"api_type":    apiType,
		"description": description,
		"nsfw":        nsfw,
		"resources":   resources,
		"title":       title,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

// GetLiveHappeningNowResponse represents the response for GET /api/live/happening_now
type GetLiveHappeningNowResponse struct {
	ShowAnnouncements bool `json:"show_announcements"` // boolean value
}

/*
GetLiveHappeningNow makes a GET request to /api/live/happening_now
ID: GET /api/live/happening_now
Description: Get some basic information about the currently featured live thread.Returns an empty 204 response for api requests if no thread is currently featured.See also: /api/live/thread/about.
*/
func (sdk *ReddiGoSDK) GetLiveHappeningNow() (GetLiveHappeningNowResponse, error) {
	reqUrl := "/api/live/happening_now"
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return GetLiveHappeningNowResponse{}, err
	}
	defer resp.Body.Close()
	var response GetLiveHappeningNowResponse
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return GetLiveHappeningNowResponse{}, err
	}
	return response, nil
}

/*
PostLiveThreadAcceptContributorInvite makes a POST request to /api/live/{thread}/accept_contributor_invite
ID: POST /api/live/{thread}/accept_contributor_invite
Description: Accept a pending invitation to contribute to the thread.See also: /api/live/thread/leave_contributor.
*/
func (sdk *ReddiGoSDK) PostLiveThreadAcceptContributorInvite(thread string, apiType string) (any, error) {
	reqUrl := fmt.Sprintf("/api/live/%s/accept_contributor_invite", thread)
	payload := map[string]interface{}{
		"api_type": apiType,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostLiveThreadCloseThread makes a POST request to /api/live/{thread}/close_{thread}
ID: POST /api/live/{thread}/close_{thread}
Description: Permanently close the thread, disallowing future updates.Requires the close permission for this thread.
*/
func (sdk *ReddiGoSDK) PostLiveThreadCloseThread(thread string, apiType string) (any, error) {
	reqUrl := fmt.Sprintf("/api/live/%s/close_%s", thread, thread)
	payload := map[string]interface{}{
		"api_type": apiType,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostLiveThreadDeleteUpdate makes a POST request to /api/live/{thread}/delete_update
ID: POST /api/live/{thread}/delete_update
Description: Delete an update from the thread.Requires that specified update must have been authored by the user or
that you have the edit permission for this thread.See also: /api/live/thread/update.
*/
func (sdk *ReddiGoSDK) PostLiveThreadDeleteUpdate(thread string, apiType string, id interface{}) (any, error) {
	reqUrl := fmt.Sprintf("/api/live/%s/delete_update", thread)
	payload := map[string]interface{}{
		"api_type": apiType,
		"id":       id,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostLiveThreadEdit makes a POST request to /api/live/{thread}/edit
ID: POST /api/live/{thread}/edit
Description: Configure the thread.Requires the settings permission for this thread.See also: /live/thread/about.json.
*/
func (sdk *ReddiGoSDK) PostLiveThreadEdit(thread string, apiType string, description interface{}, nsfw bool, resources interface{}, title string) (any, error) {
	reqUrl := fmt.Sprintf("/api/live/%s/edit", thread)
	payload := map[string]interface{}{
		"api_type":    apiType,
		"description": description,
		"nsfw":        nsfw,
		"resources":   resources,
		"title":       title,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostLiveThreadHideDiscussion makes a POST request to /api/live/{thread}/hide_discussion
ID: POST /api/live/{thread}/hide_discussion
Description: Hide a linked comment thread from the discussions sidebar and listing.Requires the discussions permission for this thread.See also: /api/live/thread/unhide_discussion.
*/
func (sdk *ReddiGoSDK) PostLiveThreadHideDiscussion(thread string, apiType string, link interface{}) (any, error) {
	reqUrl := fmt.Sprintf("/api/live/%s/hide_discussion", thread)
	payload := map[string]interface{}{
		"api_type": apiType,
		"link":     link,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

type PostLiveThreadInviteContributorTypeEnum string

const (
	PostLiveThreadInviteContributorTypeEnumLiveupdate_contributor_invite PostLiveThreadInviteContributorTypeEnum = "liveupdate_contributor_invite"
	PostLiveThreadInviteContributorTypeEnumLiveupdate_contributor        PostLiveThreadInviteContributorTypeEnum = "liveupdate_contributor"
)

/*
PostLiveThreadInviteContributor makes a POST request to /api/live/{thread}/invite_contributor
ID: POST /api/live/{thread}/invite_contributor
Description: Invite another user to contribute to the thread.Requires the manage permission for this thread.  If the recipient
accepts the invite, they will be granted the permissions specified.See also: /api/live/thread/accept_contributor_invite, and
/api/live/thread/rm_contributor_invite.
*/
func (sdk *ReddiGoSDK) PostLiveThreadInviteContributor(thread string, apiType string, name interface{}, permissions interface{}, typeValue string) (any, error) {
	reqUrl := fmt.Sprintf("/api/live/%s/invite_contributor", thread)
	payload := map[string]interface{}{
		"api_type":    apiType,
		"name":        name,
		"permissions": permissions,
		"type":        typeValue,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostLiveThreadLeaveContributor makes a POST request to /api/live/{thread}/leave_contributor
ID: POST /api/live/{thread}/leave_contributor
Description: Abdicate contributorship of the thread.See also: /api/live/thread/accept_contributor_invite, and
/api/live/thread/invite_contributor.
*/
func (sdk *ReddiGoSDK) PostLiveThreadLeaveContributor(thread string, apiType string) (any, error) {
	reqUrl := fmt.Sprintf("/api/live/%s/leave_contributor", thread)
	payload := map[string]interface{}{
		"api_type": apiType,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

type PostLiveThreadReportTypeEnum string

const (
	PostLiveThreadReportTypeEnumSpam                     PostLiveThreadReportTypeEnum = "spam"
	PostLiveThreadReportTypeEnumVoteMinusManipulation    PostLiveThreadReportTypeEnum = "vote-manipulation"
	PostLiveThreadReportTypeEnumPersonalMinusInformation PostLiveThreadReportTypeEnum = "personal-information"
	PostLiveThreadReportTypeEnumSexualizingMinusMinors   PostLiveThreadReportTypeEnum = "sexualizing-minors"
	PostLiveThreadReportTypeEnumSiteMinusBreaking        PostLiveThreadReportTypeEnum = "site-breaking"
)

/*
PostLiveThreadReport makes a POST request to /api/live/{thread}/report
ID: POST /api/live/{thread}/report
Description: Report the thread for violating the rules of reddit.
*/
func (sdk *ReddiGoSDK) PostLiveThreadReport(thread string, apiType string, typeValue string) (any, error) {
	reqUrl := fmt.Sprintf("/api/live/%s/report", thread)
	payload := map[string]interface{}{
		"api_type": apiType,
		"type":     typeValue,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostLiveThreadRmContributor makes a POST request to /api/live/{thread}/rm_contributor
ID: POST /api/live/{thread}/rm_contributor
Description: Revoke another user's contributorship.Requires the manage permission for this thread.See also: /api/live/thread/invite_contributor.
*/
func (sdk *ReddiGoSDK) PostLiveThreadRmContributor(thread string, apiType string, id string) (any, error) {
	reqUrl := fmt.Sprintf("/api/live/%s/rm_contributor", thread)
	payload := map[string]interface{}{
		"api_type": apiType,
		"id":       id,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostLiveThreadRmContributorInvite makes a POST request to /api/live/{thread}/rm_contributor_invite
ID: POST /api/live/{thread}/rm_contributor_invite
Description: Revoke an outstanding contributor invite.Requires the manage permission for this thread.See also: /api/live/thread/invite_contributor.
*/
func (sdk *ReddiGoSDK) PostLiveThreadRmContributorInvite(thread string, apiType string, id string) (any, error) {
	reqUrl := fmt.Sprintf("/api/live/%s/rm_contributor_invite", thread)
	payload := map[string]interface{}{
		"api_type": apiType,
		"id":       id,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

type PostLiveThreadSetContributorPermissionsTypeEnum string

const (
	PostLiveThreadSetContributorPermissionsTypeEnumLiveupdate_contributor_invite PostLiveThreadSetContributorPermissionsTypeEnum = "liveupdate_contributor_invite"
	PostLiveThreadSetContributorPermissionsTypeEnumLiveupdate_contributor        PostLiveThreadSetContributorPermissionsTypeEnum = "liveupdate_contributor"
)

/*
PostLiveThreadSetContributorPermissions makes a POST request to /api/live/{thread}/set_contributor_permissions
ID: POST /api/live/{thread}/set_contributor_permissions
Description: Change a contributor or contributor invite's permissions.Requires the manage permission for this thread.See also: /api/live/thread/invite_contributor and
/api/live/thread/rm_contributor.
*/
func (sdk *ReddiGoSDK) PostLiveThreadSetContributorPermissions(thread string, apiType string, name interface{}, permissions interface{}, typeValue string) (any, error) {
	reqUrl := fmt.Sprintf("/api/live/%s/set_contributor_permissions", thread)
	payload := map[string]interface{}{
		"api_type":    apiType,
		"name":        name,
		"permissions": permissions,
		"type":        typeValue,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostLiveThreadStrikeUpdate makes a POST request to /api/live/{thread}/strike_update
ID: POST /api/live/{thread}/strike_update
Description: Strike (mark incorrect and cross out) the content of an update.Requires that specified update must have been authored by the user or
that you have the edit permission for this thread.See also: /api/live/thread/update.
*/
func (sdk *ReddiGoSDK) PostLiveThreadStrikeUpdate(thread string, apiType string, id interface{}) (any, error) {
	reqUrl := fmt.Sprintf("/api/live/%s/strike_update", thread)
	payload := map[string]interface{}{
		"api_type": apiType,
		"id":       id,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostLiveThreadUnhideDiscussion makes a POST request to /api/live/{thread}/unhide_discussion
ID: POST /api/live/{thread}/unhide_discussion
Description: Unhide a linked comment thread from the discussions sidebar and listing..Requires the discussions permission for this thread.See also: /api/live/thread/hide_discussion.
*/
func (sdk *ReddiGoSDK) PostLiveThreadUnhideDiscussion(thread string, apiType string, link interface{}) (any, error) {
	reqUrl := fmt.Sprintf("/api/live/%s/unhide_discussion", thread)
	payload := map[string]interface{}{
		"api_type": apiType,
		"link":     link,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostLiveThreadUpdate makes a POST request to /api/live/{thread}/update
ID: POST /api/live/{thread}/update
Description: Post an update to the thread.Requires the update permission for this thread.See also: /api/live/thread/strike_update, and
/api/live/thread/delete_update.
*/
func (sdk *ReddiGoSDK) PostLiveThreadUpdate(thread string, apiType string, body interface{}) (any, error) {
	reqUrl := fmt.Sprintf("/api/live/%s/update", thread)
	payload := map[string]interface{}{
		"api_type": apiType,
		"body":     body,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

// GetLiveThreadResponse represents the response for GET /live/{thread}
type GetLiveThreadResponse struct {
	After   interface{} `json:"after"`    // the ID of a single update. e.g. LiveUpdate_ff87068e-a126-11e3-9f93-12313b0b3603
	Before  interface{} `json:"before"`   // the ID of a single update. e.g. LiveUpdate_ff87068e-a126-11e3-9f93-12313b0b3603
	Count   int         `json:"count"`    // a positive integer (default: 0)
	IsEmbed interface{} `json:"is_embed"` // (internal use only)
	Limit   interface{} `json:"limit"`    // the maximum number of items desired (default: 25, maximum: 100)
	Stylesr interface{} `json:"stylesr"`  // subreddit name
}

/*
GetLiveThread makes a GET request to /live/{thread}
ID: GET /live/{thread}
Description: Get a list of updates posted in this thread.See also: /api/live/thread/update.This endpoint is a listing.
*/
func (sdk *ReddiGoSDK) GetLiveThread(thread string, after string, before string, count string, limit string) (GetLiveThreadResponse, error) {
	reqUrl := fmt.Sprintf("/live/%s", thread)
	queryParams := urlpkg.Values{}
	queryParams.Add("after", after)
	queryParams.Add("before", before)
	queryParams.Add("count", count)
	queryParams.Add("limit", limit)
	reqUrl += "?" + queryParams.Encode()
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return GetLiveThreadResponse{}, err
	}
	defer resp.Body.Close()
	var response GetLiveThreadResponse
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return GetLiveThreadResponse{}, err
	}
	return response, nil
}

/*
GetLiveThreadAbout makes a GET request to /live/{thread}/about
ID: GET /live/{thread}/about
Description: Get some basic information about the live thread.See also: /api/live/thread/edit.
*/
func (sdk *ReddiGoSDK) GetLiveThreadAbout(thread string) (any, error) {
	reqUrl := fmt.Sprintf("/live/%s/about", thread)
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
GetLiveThreadContributors makes a GET request to /live/{thread}/contributors
ID: GET /live/{thread}/contributors
Description: Get a list of users that contribute to this thread.See also: /api/live/thread/invite_contributor, and
/api/live/thread/rm_contributor.
*/
func (sdk *ReddiGoSDK) GetLiveThreadContributors(thread string) (any, error) {
	reqUrl := fmt.Sprintf("/live/%s/contributors", thread)
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

// GetLiveThreadDiscussionsResponse represents the response for GET /live/{thread}/discussions
type GetLiveThreadDiscussionsResponse struct {
	After    string      `json:"after"`     // fullname of a thing
	Before   string      `json:"before"`    // fullname of a thing
	Count    int         `json:"count"`     // a positive integer (default: 0)
	Limit    interface{} `json:"limit"`     // the maximum number of items desired (default: 25, maximum: 100)
	Show     string      `json:"show"`      // (optional) the string all
	SrDetail bool        `json:"sr_detail"` // (optional) expand subreddits
}

/*
GetLiveThreadDiscussions makes a GET request to /live/{thread}/discussions
ID: GET /live/{thread}/discussions
Description: Get a list of reddit submissions linking to this thread.This endpoint is a listing.
*/
func (sdk *ReddiGoSDK) GetLiveThreadDiscussions(thread string, after string, before string, count string, limit string) (GetLiveThreadDiscussionsResponse, error) {
	reqUrl := fmt.Sprintf("/live/%s/discussions", thread)
	queryParams := urlpkg.Values{}
	queryParams.Add("after", after)
	queryParams.Add("before", before)
	queryParams.Add("count", count)
	queryParams.Add("limit", limit)
	reqUrl += "?" + queryParams.Encode()
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return GetLiveThreadDiscussionsResponse{}, err
	}
	defer resp.Body.Close()
	var response GetLiveThreadDiscussionsResponse
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return GetLiveThreadDiscussionsResponse{}, err
	}
	return response, nil
}

/*
GetLiveThreadUpdatesUpdateId makes a GET request to /live/{thread}/updates/{update_id}
ID: GET /live/{thread}/updates/{update_id}
Description: Get details about a specific update in a live thread.
*/
func (sdk *ReddiGoSDK) GetLiveThreadUpdatesUpdateId(thread string, updateId string) (any, error) {
	reqUrl := fmt.Sprintf("/live/%s/updates/%s", thread, updateId)
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostBlock makes a POST request to /api/block
ID: POST /api/block
Description: For blocking the author of a thing via inbox.
Only accessible to approved OAuth applications
*/
func (sdk *ReddiGoSDK) PostBlock(id string) (any, error) {
	reqUrl := "/api/block"
	payload := map[string]interface{}{
		"id": id,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostCollapseMessage makes a POST request to /api/collapse_message
ID: POST /api/collapse_message
Description: Collapse a messageSee also: /api/uncollapse_message
*/
func (sdk *ReddiGoSDK) PostCollapseMessage(id string) (any, error) {
	reqUrl := "/api/collapse_message"
	payload := map[string]interface{}{
		"id": id,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostCompose makes a POST request to /api/compose
ID: POST /api/compose
Description: Handles message composition under /message/compose.
*/
func (sdk *ReddiGoSDK) PostCompose(apiType string, fromSr interface{}, gRecaptchaResponse interface{}, subject string, text interface{}, to interface{}) (any, error) {
	reqUrl := "/api/compose"
	payload := map[string]interface{}{
		"api_type":             apiType,
		"from_sr":              fromSr,
		"g-recaptcha-response": gRecaptchaResponse,
		"subject":              subject,
		"text":                 text,
		"to":                   to,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostDelMsg makes a POST request to /api/del_msg
ID: POST /api/del_msg
Description: Delete messages from the recipient's view of their inbox.
*/
func (sdk *ReddiGoSDK) PostDelMsg(id string) (any, error) {
	reqUrl := "/api/del_msg"
	payload := map[string]interface{}{
		"id": id,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostReadAllMessages makes a POST request to /api/read_all_messages
ID: POST /api/read_all_messages
Description: Queue up marking all messages for a user as read.This may take some time, and returns 202 to acknowledge acceptance of
the request.
*/
func (sdk *ReddiGoSDK) PostReadAllMessages(filterTypes string) (any, error) {
	reqUrl := "/api/read_all_messages"
	payload := map[string]interface{}{
		"filter_types": filterTypes,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostReadMessage makes a POST request to /api/read_message
ID: POST /api/read_message
Description: No description available
*/
func (sdk *ReddiGoSDK) PostReadMessage(id string) (any, error) {
	reqUrl := "/api/read_message"
	payload := map[string]interface{}{
		"id": id,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostUnblockSubreddit makes a POST request to /api/unblock_subreddit
ID: POST /api/unblock_subreddit
Description: No description available
*/
func (sdk *ReddiGoSDK) PostUnblockSubreddit(id string) (any, error) {
	reqUrl := "/api/unblock_subreddit"
	payload := map[string]interface{}{
		"id": id,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostUncollapseMessage makes a POST request to /api/uncollapse_message
ID: POST /api/uncollapse_message
Description: Uncollapse a messageSee also: /api/collapse_message
*/
func (sdk *ReddiGoSDK) PostUncollapseMessage(id string) (any, error) {
	reqUrl := "/api/uncollapse_message"
	payload := map[string]interface{}{
		"id": id,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

/*
PostUnreadMessage makes a POST request to /api/unread_message
ID: POST /api/unread_message
Description: No description available
*/
func (sdk *ReddiGoSDK) PostUnreadMessage(id string) (any, error) {
	reqUrl := "/api/unread_message"
	payload := map[string]interface{}{
		"id": id,
	}
	// Construct the request for POST method
	jsonPayload, err := jsonpkg.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := sdk.MakeRequest("POST", reqUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response any
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

type GetMessageWhereMarkEnum string

const (
	GetMessageWhereMarkEnumTrue  GetMessageWhereMarkEnum = "true"
	GetMessageWhereMarkEnumFalse GetMessageWhereMarkEnum = "false"
)

// GetMessageWhereResponse represents the response for GET /message/{where}
type GetMessageWhereResponse struct {
	Mark       string      `json:"mark"`        // one of (true, false)
	MaxReplies interface{} `json:"max_replies"` // the maximum number of items desired (default: 0, maximum: 300)
	Mid        interface{} `json:"mid"`         //
	After      string      `json:"after"`       // fullname of a thing
	Before     string      `json:"before"`      // fullname of a thing
	Count      int         `json:"count"`       // a positive integer (default: 0)
	Limit      interface{} `json:"limit"`       // the maximum number of items desired (default: 25, maximum: 100)
	Show       string      `json:"show"`        // (optional) the string all
	SrDetail   bool        `json:"sr_detail"`   // (optional) expand subreddits
}

/*
GetMessageWhere makes a GET request to /message/{where}
ID: GET /message/{where}
Description: This endpoint is a listing.
*/
func (sdk *ReddiGoSDK) GetMessageWhere(where string, after string, before string, count string, limit string) (GetMessageWhereResponse, error) {
	reqUrl := fmt.Sprintf("/message/%s", where)
	queryParams := urlpkg.Values{}
	queryParams.Add("after", after)
	queryParams.Add("before", before)
	queryParams.Add("count", count)
	queryParams.Add("limit", limit)
	reqUrl += "?" + queryParams.Encode()
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return GetMessageWhereResponse{}, err
	}
	defer resp.Body.Close()
	var response GetMessageWhereResponse
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return GetMessageWhereResponse{}, err
	}
	return response, nil
}

// GetRSubredditSavedMediaTextResponse represents the response for GET /r/{subreddit}/api/saved_media_text
type GetRSubredditSavedMediaTextResponse struct {
	Url string `json:"url"` // a valid URL
}

/*
GetRSubredditSavedMediaText makes a GET request to /r/{subreddit}/api/saved_media_text
ID: GET /r/{subreddit}/api/saved_media_text
Description: Retrieve the advisory text about saving media for relevant media links.This endpoint returns a notice for display during the post submission
process that is pertinent to media links.
*/
func (sdk *ReddiGoSDK) GetRSubredditSavedMediaText(subreddit string) (GetRSubredditSavedMediaTextResponse, error) {
	reqUrl := fmt.Sprintf("/r/%s/api/saved_media_text", subreddit)
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return GetRSubredditSavedMediaTextResponse{}, err
	}
	defer resp.Body.Close()
	var response GetRSubredditSavedMediaTextResponse
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return GetRSubredditSavedMediaTextResponse{}, err
	}
	return response, nil
}

// GetScopesResponse represents the response for GET /api/v1/scopes
type GetScopesResponse struct {
	Scopes string `json:"scopes"` // (optional) An OAuth2 scope string
}

/*
GetScopes makes a GET request to /api/v1/scopes
ID: GET /api/v1/scopes
Description: Retrieve descriptions of reddit's OAuth2 scopes.If no scopes are given, information on all scopes are returned.Invalid scope(s) will result in a 400 error with body that indicates
the invalid scope(s).
*/
func (sdk *ReddiGoSDK) GetScopes() (GetScopesResponse, error) {
	reqUrl := "/api/v1/scopes"
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return GetScopesResponse{}, err
	}
	defer resp.Body.Close()
	var response GetScopesResponse
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return GetScopesResponse{}, err
	}
	return response, nil
}

type GetRSubredditAboutLogTypeEnum string

const (
	GetRSubredditAboutLogTypeEnumBanuser                           GetRSubredditAboutLogTypeEnum = "banuser"
	GetRSubredditAboutLogTypeEnumUnbanuser                         GetRSubredditAboutLogTypeEnum = "unbanuser"
	GetRSubredditAboutLogTypeEnumSpamlink                          GetRSubredditAboutLogTypeEnum = "spamlink"
	GetRSubredditAboutLogTypeEnumRemovelink                        GetRSubredditAboutLogTypeEnum = "removelink"
	GetRSubredditAboutLogTypeEnumApprovelink                       GetRSubredditAboutLogTypeEnum = "approvelink"
	GetRSubredditAboutLogTypeEnumSpamcomment                       GetRSubredditAboutLogTypeEnum = "spamcomment"
	GetRSubredditAboutLogTypeEnumRemovecomment                     GetRSubredditAboutLogTypeEnum = "removecomment"
	GetRSubredditAboutLogTypeEnumApprovecomment                    GetRSubredditAboutLogTypeEnum = "approvecomment"
	GetRSubredditAboutLogTypeEnumAddmoderator                      GetRSubredditAboutLogTypeEnum = "addmoderator"
	GetRSubredditAboutLogTypeEnumShowcomment                       GetRSubredditAboutLogTypeEnum = "showcomment"
	GetRSubredditAboutLogTypeEnumInvitemoderator                   GetRSubredditAboutLogTypeEnum = "invitemoderator"
	GetRSubredditAboutLogTypeEnumUninvitemoderator                 GetRSubredditAboutLogTypeEnum = "uninvitemoderator"
	GetRSubredditAboutLogTypeEnumAcceptmoderatorinvite             GetRSubredditAboutLogTypeEnum = "acceptmoderatorinvite"
	GetRSubredditAboutLogTypeEnumRemovemoderator                   GetRSubredditAboutLogTypeEnum = "removemoderator"
	GetRSubredditAboutLogTypeEnumAddcontributor                    GetRSubredditAboutLogTypeEnum = "addcontributor"
	GetRSubredditAboutLogTypeEnumRemovecontributor                 GetRSubredditAboutLogTypeEnum = "removecontributor"
	GetRSubredditAboutLogTypeEnumEditsettings                      GetRSubredditAboutLogTypeEnum = "editsettings"
	GetRSubredditAboutLogTypeEnumEditflair                         GetRSubredditAboutLogTypeEnum = "editflair"
	GetRSubredditAboutLogTypeEnumDistinguish                       GetRSubredditAboutLogTypeEnum = "distinguish"
	GetRSubredditAboutLogTypeEnumMarknsfw                          GetRSubredditAboutLogTypeEnum = "marknsfw"
	GetRSubredditAboutLogTypeEnumWikibanned                        GetRSubredditAboutLogTypeEnum = "wikibanned"
	GetRSubredditAboutLogTypeEnumWikicontributor                   GetRSubredditAboutLogTypeEnum = "wikicontributor"
	GetRSubredditAboutLogTypeEnumWikiunbanned                      GetRSubredditAboutLogTypeEnum = "wikiunbanned"
	GetRSubredditAboutLogTypeEnumWikipagelisted                    GetRSubredditAboutLogTypeEnum = "wikipagelisted"
	GetRSubredditAboutLogTypeEnumRemovewikicontributor             GetRSubredditAboutLogTypeEnum = "removewikicontributor"
	GetRSubredditAboutLogTypeEnumWikirevise                        GetRSubredditAboutLogTypeEnum = "wikirevise"
	GetRSubredditAboutLogTypeEnumWikipermlevel                     GetRSubredditAboutLogTypeEnum = "wikipermlevel"
	GetRSubredditAboutLogTypeEnumIgnorereports                     GetRSubredditAboutLogTypeEnum = "ignorereports"
	GetRSubredditAboutLogTypeEnumUnignorereports                   GetRSubredditAboutLogTypeEnum = "unignorereports"
	GetRSubredditAboutLogTypeEnumSetpermissions                    GetRSubredditAboutLogTypeEnum = "setpermissions"
	GetRSubredditAboutLogTypeEnumSetsuggestedsort                  GetRSubredditAboutLogTypeEnum = "setsuggestedsort"
	GetRSubredditAboutLogTypeEnumSticky                            GetRSubredditAboutLogTypeEnum = "sticky"
	GetRSubredditAboutLogTypeEnumUnsticky                          GetRSubredditAboutLogTypeEnum = "unsticky"
	GetRSubredditAboutLogTypeEnumSetcontestmode                    GetRSubredditAboutLogTypeEnum = "setcontestmode"
	GetRSubredditAboutLogTypeEnumUnsetcontestmode                  GetRSubredditAboutLogTypeEnum = "unsetcontestmode"
	GetRSubredditAboutLogTypeEnumLock                              GetRSubredditAboutLogTypeEnum = "lock"
	GetRSubredditAboutLogTypeEnumUnlock                            GetRSubredditAboutLogTypeEnum = "unlock"
	GetRSubredditAboutLogTypeEnumMuteuser                          GetRSubredditAboutLogTypeEnum = "muteuser"
	GetRSubredditAboutLogTypeEnumUnmuteuser                        GetRSubredditAboutLogTypeEnum = "unmuteuser"
	GetRSubredditAboutLogTypeEnumCreaterule                        GetRSubredditAboutLogTypeEnum = "createrule"
	GetRSubredditAboutLogTypeEnumEditrule                          GetRSubredditAboutLogTypeEnum = "editrule"
	GetRSubredditAboutLogTypeEnumReorderrules                      GetRSubredditAboutLogTypeEnum = "reorderrules"
	GetRSubredditAboutLogTypeEnumDeleterule                        GetRSubredditAboutLogTypeEnum = "deleterule"
	GetRSubredditAboutLogTypeEnumSpoiler                           GetRSubredditAboutLogTypeEnum = "spoiler"
	GetRSubredditAboutLogTypeEnumUnspoiler                         GetRSubredditAboutLogTypeEnum = "unspoiler"
	GetRSubredditAboutLogTypeEnumModmail_enrollment                GetRSubredditAboutLogTypeEnum = "modmail_enrollment"
	GetRSubredditAboutLogTypeEnumCommunity_status                  GetRSubredditAboutLogTypeEnum = "community_status"
	GetRSubredditAboutLogTypeEnumCommunity_styling                 GetRSubredditAboutLogTypeEnum = "community_styling"
	GetRSubredditAboutLogTypeEnumCommunity_welcome_page            GetRSubredditAboutLogTypeEnum = "community_welcome_page"
	GetRSubredditAboutLogTypeEnumCommunity_widgets                 GetRSubredditAboutLogTypeEnum = "community_widgets"
	GetRSubredditAboutLogTypeEnumMarkoriginalcontent               GetRSubredditAboutLogTypeEnum = "markoriginalcontent"
	GetRSubredditAboutLogTypeEnumCollections                       GetRSubredditAboutLogTypeEnum = "collections"
	GetRSubredditAboutLogTypeEnumEvents                            GetRSubredditAboutLogTypeEnum = "events"
	GetRSubredditAboutLogTypeEnumHidden_award                      GetRSubredditAboutLogTypeEnum = "hidden_award"
	GetRSubredditAboutLogTypeEnumAdd_community_topics              GetRSubredditAboutLogTypeEnum = "add_community_topics"
	GetRSubredditAboutLogTypeEnumRemove_community_topics           GetRSubredditAboutLogTypeEnum = "remove_community_topics"
	GetRSubredditAboutLogTypeEnumCreate_scheduled_post             GetRSubredditAboutLogTypeEnum = "create_scheduled_post"
	GetRSubredditAboutLogTypeEnumEdit_scheduled_post               GetRSubredditAboutLogTypeEnum = "edit_scheduled_post"
	GetRSubredditAboutLogTypeEnumDelete_scheduled_post             GetRSubredditAboutLogTypeEnum = "delete_scheduled_post"
	GetRSubredditAboutLogTypeEnumSubmit_scheduled_post             GetRSubredditAboutLogTypeEnum = "submit_scheduled_post"
	GetRSubredditAboutLogTypeEnumEdit_comment_requirements         GetRSubredditAboutLogTypeEnum = "edit_comment_requirements"
	GetRSubredditAboutLogTypeEnumEdit_post_requirements            GetRSubredditAboutLogTypeEnum = "edit_post_requirements"
	GetRSubredditAboutLogTypeEnumInvitesubscriber                  GetRSubredditAboutLogTypeEnum = "invitesubscriber"
	GetRSubredditAboutLogTypeEnumSubmit_content_rating_survey      GetRSubredditAboutLogTypeEnum = "submit_content_rating_survey"
	GetRSubredditAboutLogTypeEnumAdjust_post_crowd_control_level   GetRSubredditAboutLogTypeEnum = "adjust_post_crowd_control_level"
	GetRSubredditAboutLogTypeEnumEnable_post_crowd_control_filter  GetRSubredditAboutLogTypeEnum = "enable_post_crowd_control_filter"
	GetRSubredditAboutLogTypeEnumDisable_post_crowd_control_filter GetRSubredditAboutLogTypeEnum = "disable_post_crowd_control_filter"
	GetRSubredditAboutLogTypeEnumDeleteoverriddenclassification    GetRSubredditAboutLogTypeEnum = "deleteoverriddenclassification"
	GetRSubredditAboutLogTypeEnumOverrideclassification            GetRSubredditAboutLogTypeEnum = "overrideclassification"
	GetRSubredditAboutLogTypeEnumReordermoderators                 GetRSubredditAboutLogTypeEnum = "reordermoderators"
	GetRSubredditAboutLogTypeEnumRequest_assistance                GetRSubredditAboutLogTypeEnum = "request_assistance"
	GetRSubredditAboutLogTypeEnumSnoozereports                     GetRSubredditAboutLogTypeEnum = "snoozereports"
	GetRSubredditAboutLogTypeEnumUnsnoozereports                   GetRSubredditAboutLogTypeEnum = "unsnoozereports"
	GetRSubredditAboutLogTypeEnumAddnote                           GetRSubredditAboutLogTypeEnum = "addnote"
	GetRSubredditAboutLogTypeEnumDeletenote                        GetRSubredditAboutLogTypeEnum = "deletenote"
	GetRSubredditAboutLogTypeEnumAddremovalreason                  GetRSubredditAboutLogTypeEnum = "addremovalreason"
	GetRSubredditAboutLogTypeEnumCreateremovalreason               GetRSubredditAboutLogTypeEnum = "createremovalreason"
	GetRSubredditAboutLogTypeEnumUpdateremovalreason               GetRSubredditAboutLogTypeEnum = "updateremovalreason"
	GetRSubredditAboutLogTypeEnumDeleteremovalreason               GetRSubredditAboutLogTypeEnum = "deleteremovalreason"
	GetRSubredditAboutLogTypeEnumReorderremovalreason              GetRSubredditAboutLogTypeEnum = "reorderremovalreason"
	GetRSubredditAboutLogTypeEnumDev_platform_app_changed          GetRSubredditAboutLogTypeEnum = "dev_platform_app_changed"
	GetRSubredditAboutLogTypeEnumDev_platform_app_disabled         GetRSubredditAboutLogTypeEnum = "dev_platform_app_disabled"
	GetRSubredditAboutLogTypeEnumDev_platform_app_enabled          GetRSubredditAboutLogTypeEnum = "dev_platform_app_enabled"
	GetRSubredditAboutLogTypeEnumDev_platform_app_installed        GetRSubredditAboutLogTypeEnum = "dev_platform_app_installed"
	GetRSubredditAboutLogTypeEnumDev_platform_app_uninstalled      GetRSubredditAboutLogTypeEnum = "dev_platform_app_uninstalled"
	GetRSubredditAboutLogTypeEnumEdit_saved_response               GetRSubredditAboutLogTypeEnum = "edit_saved_response"
	GetRSubredditAboutLogTypeEnumChat_approve_message              GetRSubredditAboutLogTypeEnum = "chat_approve_message"
	GetRSubredditAboutLogTypeEnumChat_remove_message               GetRSubredditAboutLogTypeEnum = "chat_remove_message"
	GetRSubredditAboutLogTypeEnumChat_ban_user                     GetRSubredditAboutLogTypeEnum = "chat_ban_user"
	GetRSubredditAboutLogTypeEnumChat_unban_user                   GetRSubredditAboutLogTypeEnum = "chat_unban_user"
	GetRSubredditAboutLogTypeEnumChat_invite_host                  GetRSubredditAboutLogTypeEnum = "chat_invite_host"
	GetRSubredditAboutLogTypeEnumChat_remove_host                  GetRSubredditAboutLogTypeEnum = "chat_remove_host"
	GetRSubredditAboutLogTypeEnumApprove_award                     GetRSubredditAboutLogTypeEnum = "approve_award"
)

// GetRSubredditAboutLogResponse represents the response for GET /r/{subreddit}/about/log
type GetRSubredditAboutLogResponse struct {
	After     interface{} `json:"after"`     // a ModAction ID
	Before    interface{} `json:"before"`    // a ModAction ID
	Count     int         `json:"count"`     // a positive integer (default: 0)
	Limit     interface{} `json:"limit"`     // the maximum number of items desired (default: 25, maximum: 500)
	Mod       interface{} `json:"mod"`       // (optional) a moderator filter
	Show      string      `json:"show"`      // (optional) the string all
	SrDetail  bool        `json:"sr_detail"` // (optional) expand subreddits
	TypeValue string      `json:"type"`      // one of (banuser, unbanuser, spamlink, removelink, approvelink, spamcomment, removecomment, approvecomment, addmoderator, showcomment, invitemoderator, uninvitemoderator, acceptmoderatorinvite, removemoderator, addcontributor, removecontributor, editsettings, editflair, distinguish, marknsfw, wikibanned, wikicontributor, wikiunbanned, wikipagelisted, removewikicontributor, wikirevise, wikipermlevel, ignorereports, unignorereports, setpermissions, setsuggestedsort, sticky, unsticky, setcontestmode, unsetcontestmode, lock, unlock, muteuser, unmuteuser, createrule, editrule, reorderrules, deleterule, spoiler, unspoiler, modmail_enrollment, community_status, community_styling, community_welcome_page, community_widgets, markoriginalcontent, collections, events, hidden_award, add_community_topics, remove_community_topics, create_scheduled_post, edit_scheduled_post, delete_scheduled_post, submit_scheduled_post, edit_comment_requirements, edit_post_requirements, invitesubscriber, submit_content_rating_survey, adjust_post_crowd_control_level, enable_post_crowd_control_filter, disable_post_crowd_control_filter, deleteoverriddenclassification, overrideclassification, reordermoderators, request_assistance, snoozereports, unsnoozereports, addnote, deletenote, addremovalreason, createremovalreason, updateremovalreason, deleteremovalreason, reorderremovalreason, dev_platform_app_changed, dev_platform_app_disabled, dev_platform_app_enabled, dev_platform_app_installed, dev_platform_app_uninstalled, edit_saved_response, chat_approve_message, chat_remove_message, chat_ban_user, chat_unban_user, chat_invite_host, chat_remove_host, approve_award)
}

/*
GetRSubredditAboutLog makes a GET request to /r/{subreddit}/about/log
ID: GET /r/{subreddit}/about/log
Description: Get a list of recent moderation actions.Moderator actions taken within a subreddit are logged. This listing is
a view of that log with various filters to aid in analyzing the
information.The optional mod parameter can be a comma-delimited list of moderator
names to restrict the results to, or the string a to restrict the
results to admin actions taken within the subreddit.The type parameter is optional and if sent limits the log entries
returned to only those of the type specified.This endpoint is a listing.
*/
func (sdk *ReddiGoSDK) GetRSubredditAboutLog(subreddit string, after string, before string, count string, limit string) (GetRSubredditAboutLogResponse, error) {
	reqUrl := fmt.Sprintf("/r/%s/about/log", subreddit)
	queryParams := urlpkg.Values{}
	queryParams.Add("after", after)
	queryParams.Add("before", before)
	queryParams.Add("count", count)
	queryParams.Add("limit", limit)
	reqUrl += "?" + queryParams.Encode()
	// Construct the request for GET method
	resp, err := sdk.MakeRequest("GET", reqUrl, nil)
	if err != nil {
		return GetRSubredditAboutLogResponse{}, err
	}
	defer resp.Body.Close()
	var response GetRSubredditAboutLogResponse
	if err := jsonpkg.NewDecoder(resp.Body).Decode(&response); err != nil {
		return GetRSubredditAboutLogResponse{}, err
	}
	return response, nil
}
