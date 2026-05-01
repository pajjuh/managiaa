# Managiaa 🚀

**Managiaa** is a premium, high-performance Task and Project Management system designed for modern teams. Built with a focus on visual excellence and intuitive user experience, it combines powerful backend logic with a stunning glassmorphic UI.

![Dashboard Preview](static/img/full%20logo.png)

## ✨ Key Features

- **Dynamic Performance Dashboard**: Real-time analytics with interactive charts (Chart.js) tracking task efficiency and priority distribution.
- **Advanced Project Management**: Organize tasks into projects with visual progress tracking and roadmap-style displays.
- **Intelligent Task Tracking**: Manage task lifecycles with statuses, priorities, and automated progress bars.
- **Premium UI/UX**:
  - Seamless **Dark & Light Mode** support with persistent user preferences.
  - Modern **Glassmorphic Design** with refined typography and vibrant accents.
  - Responsive layout for both desktop and mobile workflows.
- **Secure Architecture**: Powered by Supabase for reliable authentication and scalable PostgreSQL data management.
- **Role-Based Access Control**: Administrative oversight with audit logging for enhanced security.

## 🛠️ Tech Stack

- **Backend**: Python / Flask
- **Database**: Supabase (PostgreSQL)
- **Frontend**: HTML5, Vanilla CSS3 (Custom Variables), JavaScript (ES6+)
- **Styling**: Bootstrap 5.3 + Custom Premium Components
- **Visualization**: Chart.js 4.x
- **Icons**: Bootstrap Icons

## 🚀 Getting Started

### Prerequisites
- Python 3.8+
- Supabase Account

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/pajjuh/managiaa.git
   cd managiaa
   ```

2. **Set up virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Environment Configuration**
   Create a `.env` file in the root directory and add your Supabase credentials:
   ```env
   SUPABASE_URL=your_supabase_url
   SUPABASE_KEY=your_supabase_key
   SECRET_KEY=your_flask_secret_key
   ```

5. **Run the application**
   ```bash
   python app.py
   ```

## 🎨 Design Philosophy

Managiaa is built on the principle of **Visual Clarity**. Every component, from the high-radius glass cards to the pill-shaped badges, is meticulously designed to reduce cognitive load while maintaining a high-end aesthetic.

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.

---
Created with ❤️ by [Pajjuh](https://github.com/pajjuh)
