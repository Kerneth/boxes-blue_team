# Triage Log – Phishing Unfolding

This document summarizes all phishing-related alerts observed during the SOC Simulator run.

| Time (UTC) | Alert ID | Alert Type | Sender | Recipient | Subject | Verdict | Severity | Notes |
|-----------|--------|-----------|--------|---------|--------|--------|--------|-------|
| 14:31:46 | 1000 | Suspicious email | eileen@trendymillineryco.me | support@tryhatme.com | Inheritance Alert: Unknown Billionaire Relative Left You Their Hat Fortunes | True Positive (Spam) | Low | Classic inheritance scam, social engineering |
| 14:36:52 | 1011 | Suspicious email | keane@modernmillinerygroup.online | michael.ascot@tryhatme.com | Amazing Hat Enhancement Pills Grow Your Hat Collection Instantly | True Positive (Spam) | Low | Unrealistic marketing, suspicious TLD |
| 14:39:49 | 1017 | Suspicious email | osman@fashionindustrytrends.xyz | kyra.flores@tryhatme.com | Time Traveling Hat Adventure Explore Ancient Lands for Cheap | True Positive (Spam) | Low | Unusual domain, marketing scam |
| 14:52:48 | 1013 | Suspicious email | griffin@hatventuresworldwide.online | armaan.terry@tryhatme.com | Work from Home and Make 10000 a Day Scam Alert | True Positive (Spam) | Low | Work-from-home scam pattern |
| 14:59:49 | 1014 | Suspicious email | odom@gmail.com | liam.espinoza@tryhatme.com | Exclusive Offer: Buy 100 Hats Get 99 Free Limited Time Only | True Positive (Spam) | Low | Free offer scam |
| 15:00:32 | 1017 | Suspicious email | stone@fashionindustrytrends.xyz | armaan.terry@tryhatme.com | Time Traveling Hat Adventure Explore Ancient Lands for Cheap | True Positive (Spam) | Low | Marketing spam, suspicious sender domain |

## Summary

- All alerts were classified as **True Positive – Spam / Phishing**  
- No user interaction or compromise observed for these alerts  
- Detection rule requires tuning to reduce noise from marketing spam

## Recommended Actions

- Block sender domains at the email gateway  
- Tune phishing detection rules to reduce false positives  
- Provide user awareness reminder
