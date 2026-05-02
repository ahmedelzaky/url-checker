# URL Checker

A modern web application that analyzes URLs for phishing and malware threats using heuristic checks and VirusTotal integration.

## Features

- **Local Heuristic Analysis**: Scans URL structure for common phishing patterns and security red flags
- **VirusTotal Integration**: Submits URLs to VirusTotal for comprehensive malware and security scanning
- **Real-time Results**: Displays detection statistics from multiple security engines
- **Community Reputation**: Shows reputation scores from the security community
- **Responsive UI**: Beautiful, mobile-friendly interface built with Tailwind CSS and Radix UI components

## Tech Stack

- **Frontend**: React 19, TanStack Router
- **Styling**: Tailwind CSS, Radix UI components
- **Type Safety**: TypeScript
- **API Integration**: VirusTotal API v3 (client-side)
- **Build Tool**: Vite

## Getting Started

### Prerequisites

- Node.js 18+
- pnpm (or npm/yarn)
- VirusTotal API key (get one at https://www.virustotal.com/gui/home/upload)

### Installation

1. Clone the repository:

```bash
git clone https://github.com/ahmedelzaky/url-checker.git
cd url-checker
```

2. Install dependencies:

```bash
pnpm install
```

3. Set up environment variables:

Create a `.env` file (or `.env.local`) in the project root:

```
VITE_VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
```

### Running Locally

Start the development server:

```bash
pnpm dev
```

The application will be available at `http://localhost:5173`

### Building for Production

```bash
pnpm build
```

Outputs:

- Client bundle: `dist/`

### Preview Production Build

```bash
pnpm preview
```

## Project Structure

```
src/
├── api/
│   └── virustotal.functions.ts    # VirusTotal API client-side functions
├── components/
│   ├── UrlChecker.tsx             # Main URL checking component
│   └── ui/                        # Radix UI component library
├── hooks/
│   ├── use-mobile.tsx             # Mobile detection hook
│   └── useVirusTotal.tsx          # VirusTotal scanning hook
├── lib/
│   ├── urlChecker.ts              # URL heuristic checking logic
│   └── utils.ts                   # Utility functions
├── routes/
│   ├── __root.tsx                 # Root route layout
│   └── index.tsx                  # Home page
└── styles.css                     # Global styles
```

## Key Components

### `useVirusTotal` Hook

React hook that manages VirusTotal URL scanning state and provides:

- `scan(url)` - Initiates a scan for the given URL
- `result` - The scan result object
- `loading` - Loading state during scan

**Usage:**

```typescript
const { scan, result, loading } = useVirusTotal();

await scan("https://example.com");
if (result?.ok) {
  console.log(result.stats);
}
```

### `urlChecker` Library

Analyzes URLs locally for common phishing indicators:

- Suspicious domain patterns
- Port mismatches
- Protocol warnings
- URL structure validation

Returns a `CheckResult` with:

- `score` - Safety score (0-100)
- `rating` - Safety level (Safe, Likely Safe, Suspicious, Dangerous)
- `issues` - Array of security issues found
- `passed` - Checks that passed

## API Integration

The app uses VirusTotal API v3 for comprehensive URL scanning:

1. **Submit URL** - Submits the URL for analysis
2. **Poll Analysis** - Waits for VirusTotal engines to complete scanning (up to 15 seconds)
3. **Fetch Results** - Retrieves detection stats and community reputation

Scan result includes:

- Detection counts (malicious, suspicious, harmless, undetected, timeout)
- Community reputation score
- Total engines that scanned the URL
- Scan date and VirusTotal report link

## Scripts

```bash
pnpm dev       # Start development server
pnpm build     # Build for production
pnpm preview   # Preview production build
pnpm lint      # Run ESLint
pnpm format    # Format code with Prettier
```

## Environment Variables

| Variable                  | Description                         | Required |
| ------------------------- | ----------------------------------- | -------- |
| `VITE_VIRUSTOTAL_API_KEY` | VirusTotal API key for URL scanning | Yes      |

## Architecture

The application is **fully client-side**:
- All API calls to VirusTotal run directly from the browser
- No backend server required
- Uses Vite for development and production builds
- TanStack Router for client-side routing

**Note**: The VirusTotal API key is exposed in the browser. For production, consider implementing a backend proxy to protect your API key.

## Type Safety

The project uses TypeScript with strict typing throughout:
- `VirusTotalResult` - API response type
- `VirusTotalStats` - Virus detection statistics
- `CheckResult` - Heuristic analysis result
- `Severity` - Issue severity levels (high, medium, low)

## License

This project is part of a lab assignment.

## Author

**Eng-Alaa-Gawish**
