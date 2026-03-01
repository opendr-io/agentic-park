# Rate Limiting Configuration

The alert analyst now has **dual rate limiting** to prevent exceeding Anthropic API limits.

## Two-Layer Protection

### 1. Time-Based Rate Limiting
**Setting:** `ALERT_ANALYSIS_DELAY=2.0` (seconds)

- Simple fixed delay between alert analyses
- Prevents rapid-fire requests
- Default: 2 seconds between alerts

### 2. Token-Based Rate Limiting
**Settings:**
- `TOKENS_PER_ALERT=10000` - Estimated tokens per alert (input + output)
- `MAX_TOKENS_PER_MINUTE=40000` - Maximum tokens allowed per minute

**How it works:**
- Tracks token usage in a sliding 1-minute window
- Before each API call, checks if adding this request would exceed the limit
- If limit would be exceeded, automatically waits until the oldest request falls outside the 1-minute window
- Records actual usage after each request

## Configuration by API Tier

Adjust `MAX_TOKENS_PER_MINUTE` based on your Anthropic API tier:

| Tier | Tokens/Minute | Recommended Setting |
|------|---------------|---------------------|
| Free | 40,000 | `MAX_TOKENS_PER_MINUTE=30000` |
| Build (Tier 1) | 80,000 | `MAX_TOKENS_PER_MINUTE=70000` |
| Scale (Tier 2) | 400,000 | `MAX_TOKENS_PER_MINUTE=350000` |
| Enterprise | Custom | Set based on your limit |

## Estimating Tokens Per Alert

The default `TOKENS_PER_ALERT=10000` is conservative. Adjust based on your alerts:

- **Small alerts** (5-10 events): ~3,000-5,000 tokens
- **Medium alerts** (10-50 events): ~8,000-15,000 tokens
- **Large alerts** (50+ events): ~15,000-30,000 tokens

**To estimate accurately:**
1. Monitor your first few analyses in the logs
2. Check actual token usage (if logged by LangChain)
3. Adjust `TOKENS_PER_ALERT` to match your average

## Behavior When Limit Reached

When the token limit would be exceeded, you'll see:

```
⏱ Token rate limit: 38,000/40,000 tokens used
Waiting 45.3s to stay within limits...
```

The system automatically:
1. Calculates how long to wait
2. Pauses execution
3. Resumes when safe to proceed

## Example Scenario

**Settings:**
- `MAX_TOKENS_PER_MINUTE=40000`
- `TOKENS_PER_ALERT=12000`

**Timeline:**
- 00:00 - Alert #1 analyzed (12k tokens)
- 00:10 - Alert #2 analyzed (12k tokens)
- 00:20 - Alert #3 analyzed (12k tokens)
- 00:30 - Alert #4 queued (would be 48k total)
- **WAIT** - System pauses 30s until Alert #1 expires from 1-min window
- 01:00 - Alert #4 analyzed (now only 36k in window)

## Tuning for Performance

**If analyses are too slow:**
1. Increase `MAX_TOKENS_PER_MINUTE` (if your tier allows)
2. Reduce `TOKENS_PER_ALERT` estimate (but risk hitting limits)
3. Decrease `ALERT_ANALYSIS_DELAY`

**If you're still hitting rate limits:**
1. Decrease `MAX_TOKENS_PER_MINUTE` to 80% of your tier limit (safety margin)
2. Increase `TOKENS_PER_ALERT` estimate
3. Increase `ALERT_ANALYSIS_DELAY` to 3-5 seconds

## Monitoring

All rate limiting activity is logged to `logging/alert_analysis.log`:

```
[2025-01-15 14:30:22] [__main__] [INFO] Time-based rate limiting: 2.0s delay between alerts
[2025-01-15 14:30:22] [__main__] [INFO] Token-based rate limiting: 10,000 tokens/alert, 40,000 max tokens/min
[2025-01-15 14:32:15] [__main__] [INFO] Token rate limit: 38,000/40,000 tokens used
[2025-01-15 14:32:15] [__main__] [INFO] Waiting 45.3s to stay within limits...
```

## Technical Details

The `TokenRateLimiter` class:
- Uses `collections.deque` for efficient FIFO queue
- Tracks `(timestamp, tokens)` tuples
- Auto-cleans entries older than 1 minute
- Calculates wait time dynamically based on oldest entry
- No external API calls - all tracking is local

## Fallback Behavior

If token tracking fails or encounters errors:
- Falls back to time-based delay only
- Logs warning but continues processing
- Never crashes the analysis pipeline
