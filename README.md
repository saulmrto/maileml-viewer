# MailEML Viewer

**🌍 Available in English and Spanish** | **Disponible en inglés y español**

A powerful web-based application for browsing, viewing, and managing email backups downloaded as `.eml` files. This tool provides an intuitive interface to explore your email archives with advanced filtering, spam detection, and seamless integration with [POP3 Mail Downloader](https://github.com/saulmrto/pop3mail-downloader).

## ✨ Features

### 📧 Email Management
- **Comprehensive Email Listing**: View all backed-up emails with detailed information
- **Paginated Interface**: Navigate through large email collections efficiently
- **Email Preview**: Open simplified HTML previews in new browser tabs
- **Direct Downloads**: Download original `.eml` files instantly

### 🔍 Advanced Filtering
- **Multi-criteria Search**: Filter by Subject, Sender, Recipient, or Date
- **Real-time Results**: Instant filtering with responsive interface
- **Smart Matching**: Flexible search terms for better results

### 📊 Display Options
- **Customizable Pagination**: Show 10, 20, 50, or 100 emails per page
- **Direct Page Navigation**: Jump to specific page numbers
- **Responsive Design**: Optimized for different screen sizes

### 🛡️ Spam Detection & Safety
- **Visual Spam Indicators**: Highlighted spam emails with distinct styling
- **Confirmation Modals**: Safety warnings before viewing/downloading spam
- **Configurable Rules**: Customizable spam detection via `spam_settings.json`
- **Multi-layer Filtering**: Whitelist/blacklist for emails, domains, and keywords

### 💾 Data Management
- **Automatic Directory Detection**: Uses standard `Pop3MailDownloader_UserData` structure
- **Metadata Integration**: Leverages consolidated email metadata
- **File Organization**: Maintains original email folder structure

## 📋 Prerequisites

### Required Components
1. **Python 3.x**: For running the server component
2. **POP3 Mail Downloader**: Must be run first to generate email data
3. **Modern Web Browser**: Chrome, Firefox, Edge, or Safari

### Data Requirements
The application requires data generated by [POP3 Mail Downloader](https://github.com/saulmrto/pop3mail-downloader):
- `emails_metadata.json`: Email metadata file
- `emails/` directory: Organized `.eml` files
- `Pop3MailDownloader_UserData/` directory in Documents folder

## 🚀 Installation & Setup

### 1. Generate Email Data
**Important**: Run [POP3 Mail Downloader](https://github.com/saulmrto/pop3mail-downloader) first:
```bash
# Download and run the email downloader
python main.py  # from pop3mail-downloader directory
```

This creates the required directory structure in your Documents folder.

### 2. Configure Spam Settings (Optional)
Create or edit `Pop3MailDownloader_UserData/spam_settings.json`:

```json
{
  "score_limit": 5,
  "blacklist_words": ["lottery", "urgent prize", "free money"],
  "blacklist_emails": ["spammer@example.com"],
  "blacklist_domains": ["spamdomain.com", "suspicious.net"],
  "whitelist_words": ["important report", "meeting summary"],
  "whitelist_emails": ["trusted@company.com"],
  "whitelist_domains": ["mycompany.com", "partner.org"]
}
```

### 3. Start the Server
```bash
# Navigate to the maileml-viewer directory
cd /path/to/maileml-viewer

# Run the server
python server.py
```

The server starts on `http://0.0.0.0:8000` by default.

### 4. Access the Interface
Open your web browser and navigate to:
- **Local access**: `http://localhost:8000`
- **Network access**: `http://[your-ip-address]:8000`

## 🎯 Usage Guide

### 📋 Main Interface
The main page displays a paginated table with:
- **Date & Time**: When the email was received
- **Subject**: Email subject line
- **Sender**: Email sender address
- **Recipient**: POP3 mailbox that received the email
- **Size**: Email file size
- **Actions**: View and Download buttons

### 🔍 Filtering Options
Use the filter bar at the top to search by:
- **Subject**: Search for keywords in email subjects
- **Sender**: Filter by sender email address
- **Recipient**: Filter by receiving POP3 account
- **Date**: Find emails from specific dates

Click "Apply Filter" to see results.

### 👁️ Viewing Emails
Click "Ver" (View) to open an email preview featuring:
- **Header Information**: Date, From, To, CC, Subject, Account
- **Body Content**: HTML rendering or plain text
- **Download Option**: Direct download from preview page

### 📥 Downloading Emails
- Click "Descargar" (Download) from the email list
- Or use the download button in the email preview
- Original `.eml` files are downloaded with proper formatting

### ⚠️ Spam Handling
- **Visual Indicators**: Spam emails highlighted with red styling
- **Safety Modals**: Confirmation required before viewing/downloading spam
- **Smart Detection**: Multi-layered spam identification system

## 🏗️ Architecture

### Server Component (`server.py`)
- **HTTP Server**: Serves web interface and handles API requests
- **API Endpoints**:
  - `/list-eml`: List and filter emails
  - `/view-html-eml`: Generate email previews
  - `/download-eml`: Download original files
- **Data Processing**: Reads metadata and applies spam filtering
- **File Access**: Serves `.eml` files from organized directory structure

### Client Interface (`index.html`)
- **Single Page Application**: Complete interface in one HTML file
- **Dynamic Rendering**: JavaScript-powered email list and pagination
- **Interactive Features**: Real-time filtering and user interactions
- **Responsive Design**: CSS styling for various screen sizes

## 🛡️ Spam Detection Logic

The application uses a prioritized spam detection system:

1. **Sender Whitelist**: Whitelisted emails/domains are never spam
2. **Subject Whitelist**: Emails with whitelisted keywords are safe
3. **Sender Blacklist**: Blacklisted emails/domains are marked as spam
4. **Subject Blacklist**: Emails with blacklisted keywords are spam
5. **Score Threshold**: Emails exceeding spam score limit are flagged
6. **Default**: All other emails are considered safe

### Configuration Priority
- User-defined `spam_settings.json` settings
- Metadata flags from POP3 Mail Downloader
- Built-in default settings

## 📁 Expected Directory Structure

```
Documents/Pop3MailDownloader_UserData/
├── emails_metadata.json           # Required: Email metadata
├── spam_settings.json            # Optional: Spam filter settings
└── emails/                       # Required: Email files
    ├── user1@example.com/
    │   └── *.eml files
    └── user2@example.com/
        └── *.eml files
```

## 🔗 Integration with POP3 Mail Downloader

This application is designed as a companion to POP3 Mail Downloader:

1. **Data Dependency**: Requires metadata and files from the downloader
2. **Shared Configuration**: Uses same directory structure and settings
3. **Seamless Workflow**: Download emails → Browse with viewer
4. **Consistent Experience**: Matching language support and UI patterns

## 🐛 Troubleshooting

### Common Issues

**"No emails found" message:**
- Verify POP3 Mail Downloader has been run
- Check that `emails_metadata.json` exists
- Ensure email files are in the correct directory

**Server won't start:**
- Verify Python 3.x is installed
- Check that port 8000 is available
- Ensure proper file permissions

**Emails not displaying:**
- Verify metadata file format
- Check browser console for JavaScript errors
- Confirm directory permissions

### Debug Information
- Server logs appear in the terminal
- Browser developer tools show client-side errors
- Check file timestamps to verify recent downloads

## 🔒 Security Notes

- **Local Network Only**: Server designed for local/trusted network use
- **No Authentication**: Interface has no built-in user authentication
- **File Access**: Server can access any file in the user data directory
- **Spam Warnings**: Always exercise caution with flagged emails

## 📄 License

This project is open source. Please check the repository for license details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

---

**Perfect Companion Tools:**
- Use with [POP3 Mail Downloader](https://github.com/saulmrto/pop3mail-downloader) for complete email management
- Ideal for email archiving, backup review, and offline email access
