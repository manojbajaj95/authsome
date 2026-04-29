# Providers

Authsome ships with built-in providers, ready to use with zero configuration.

## Bundled Providers

**Developer & Productivity**
`github` · `google` · `linear` · `okta` · `zapier` · `calendly` · `savvycal` · `typeform` · `buffer`

**AI & Data**
`openai` · `clearbit` · `ahrefs` · `semrush` · `g2` · `keywords-everywhere`

**Marketing & Email**
`mailchimp` · `klaviyo` · `brevo` · `sendgrid` · `postmark` · `resend` · `beehiiv` · `instantly` · `lemlist`

**Sales & CRM**
`apollo` · `hunter` · `intercom` · `mention-me` · `rewardful` · `tolt`

**Media & Analytics**
`wistia` · `livestorm` · `optimizely` · `x` · `dub`

## Custom Providers

Drop a JSON file at `~/.authsome/providers/my-service.json`:

```json
{
  "name": "my-service",
  "display_name": "My Service",
  "auth_type": "api_key",
  "flow": "api_key",
  "host_url": "api.my-service.com",
  "api_key": {
    "header_name": "X-API-Key",
    "header_prefix": "",
    "env_var": "MY_SERVICE_KEY"
  }
}
```

For APIs served from multiple hosts, `host_url` can use an explicit regular expression with the `regex:` prefix, for example `"regex:^api[0-9]+\\.github\\.com$"`.

Then use it like any bundled provider:

```bash
authsome login my-service
authsome get my-service --show-secret
```
