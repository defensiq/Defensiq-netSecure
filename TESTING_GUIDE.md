# Testing Domain Blocking - Quick Guide

## How Domain Blocking Works

Defensiq blocks domains through **3 mechanisms**:

### 1. DNS Query Blocking 
When you visit a domain (e.g., `malware.com`), your computer makes a DNS request to resolve the domain to an IP address. Defensiq intercepts these DNS queries and blocks them if the domain is in your blocklist.

### 2. DNS Response Caching
When DNS responses come back, Defensiq caches the IP↔️Domain mapping. Future connections to that IP are checked against the blocklist.

### 3. HTTP Host Header Inspection
For HTTP traffic (port 80), Defensiq inspects the Host header in HTTP requests to identify the domain being accessed, even if DNS wasn't caught.

## Testing Steps

### Step 1: Add Domains to Blocklist

1. **Launch Defensiq as Administrator** (required for filtering):
   ```bash
   # Right-click PowerShell -> Run as Administrator
   cd "E:\Coding projects\Defensiq Network security"
   python main.py
   ```

2. **Open Blocklist Tab**

3. **Add Test Domains**:
   - Click "Add Domain"
   - Add: `example.com` (safe test domain)
   - Add: `httpbin.org` (HTTP testing site)

### Step 2: Enable Filtering

1. **Toggle Filtering ON** (header toggle switch)
2. **Confirm Admin Prompt** if asked
3. **Check Status**: Header should show "🛡️ Filtering Active" in green

### Step 3: Test Domain Blocking

**Method 1: Browser Test**
```bash
# Try to access blocked domain
# Should fail to connect or timeout
http://example.com
```

**Method 2: Command Line Test**
```bash
# Try ping (DNS will be blocked)
ping example.com
# Should show "could not find host"

# Try curl/wget
curl http://example.com
# Should timeout or fail
```

**Method 3: Check Logs**
- Go to **Logs & Reports** tab
- Look for entries like:
  ```
  TRAFFIC_BLOCKED: Blocked DNS (custom): example.com - Exact match
  ```

### Step 4: Verify Blocking

1. **Check "Blocked" stat card** - should increment
2. **View Logs tab** - should see blocked entries
3. **Export logs** to verify blocking events

## Troubleshooting

### "Still able to access domain"

**Possible Causes:**

1. **Filtering not enabled**
   - Check header shows "🛡️ Filtering Active"
   - Try toggling OFF then ON again

2. **Not running as Administrator**
   - Close application
   - Right-click PowerShell -> "Run as Administrator"
   - Run `python main.py` again

3. **Browser DNS Cache**
   - Clear browser cache
   - Use `ipconfig /flushdns` (Windows)
   - Try in Incognito/Private mode

4. **HTTPS (port 443) blocking**
   - Current implementation works best on HTTP and DNS
   - HTTPS requires more advanced inspection
   - Try HTTP-only sites first (e.g., `http://example.com`)

5. **DNS already cached**
   - Flush Windows DNS: `ipconfig /flushdns`
   - Restart browser
   - Wait a few minutes for cache to clear

### "PyDivert errors"

- Make sure PyDivert is installed: `pip install pydivert`
- Run as Administrator
- Check Windows Firewall isn't blocking

## What Gets Logged

When a domain is blocked, you'll see entries like:

```
[2025-12-07 19:55:00] TRAFFIC_BLOCKED: Blocked DNS (custom): example.com - Exact match
[2025-12-07 19:55:01] TRAFFIC_BLOCKED: Blocked HTTP/HTTPS to example.com (custom): Exact match
```

## Best Test Domains

Safe domains for testing (won't harm your system):

- `example.com` - Official test domain
- `example.org` - Official test domain  
- `example.net` - Official test domain
- `httpbin.org` - HTTP testing service

**DO NOT** test with actual malware domains - use the examples above!

## Import Pre-made Blocklists

Instead of adding one-by-one:

1. **Blocklist Tab** → **Import List**
2. **Select** `config/example_blocklist.json`
3. **Verify** import count
4. **Check** Blocklist table shows entries

## Verification Checklist

- ✅ Filtering toggle ON (green "Filtering Active")
- ✅ Running as Administrator  
- ✅ Domain added to blocklist (visible in table)
- ✅ DNS cache flushed (`ipconfig /flushdns`)
- ✅ Browser cache cleared
- ✅ Blocked count incrementing
- ✅ Logs showing TRAFFIC_BLOCKED events

## Advanced: Monitor in Real-Time

**PowerShell (separate window):**
```powershell
# Watch log file in real-time
Get-Content "logs\security_events.log" -Wait -Tail 20
```

You should see blocking events appear as you try to access blocked domains.

---

**Note**: Domain blocking at the application level has limitations. For comprehensive blocking, consider DNS-level filtering (e.g., Pi-hole) or enterprise firewalls. Defensiq provides visibility and basic protection for educational and personal use.
