"""Modern theme for the IDE.

Provides a centralized theme module with light (default) and dark palettes.
Uses a subtle blue accent color for interactive elements while keeping
a clean, professional monochrome base. All UI colors, fonts, and QSS
are defined here to keep widgets free of hard-coded styling.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto

from PySide6.QtGui import QFont


class ThemeMode(Enum):
    LIGHT = auto()
    DARK = auto()


# -----------------------------------------------------------------------
# Design tokens: named constants for UI metrics and fonts
# -----------------------------------------------------------------------

# Fonts
FONT_FAMILY = '"Segoe UI", "SF Pro Text", "Inter", sans-serif'
MONO_FONT_FAMILY = '"Cascadia Code", "Consolas", monospace'
MONO_FONT_SIZE = 10


def mono_font() -> QFont:
    """Return the application-wide monospace font."""
    return QFont("Cascadia Code", MONO_FONT_SIZE)


# -----------------------------------------------------------------------
# Syntax highlighting tokens (light theme; dark theme can extend later)
# -----------------------------------------------------------------------

SYNTAX_TOKENS: dict[str, tuple[str, bool]] = {
    # token suffix → (hex colour, bold)
    "Token.Comment":       ("#008000", False),
    "Token.Keyword":       ("#0000FF", True),
    "Token.Literal.String": ("#A31515", False),
    "Token.Literal.Number": ("#098658", False),
    "Token.Name.Builtin":  ("#267F99", False),
    "Token.Name.Function": ("#795E26", False),
    "Token.Name.Class":    ("#267F99", True),
    "Token.Name.Decorator": ("#795E26", False),
    "Token.Name.Attribute": ("#E50000", False),
    "Token.Operator":      ("#000000", False),
    "Token.Name.Variable": ("#001080", False),
}


def markdown_css(accent: str = "#3b82f6") -> str:
    """Return the CSS string used inside the markdown preview HTML template.

    Colours are parameterised so the caller can pass a theme-appropriate
    accent colour (currently only the link colour varies).
    """
    return f"""\
body {{ font-family: {FONT_FAMILY}; font-size: 14px; margin: 16px; }}
pre, code {{ font-family: {MONO_FONT_FAMILY}; }}
pre {{ font-size: 13px; background: #f6f8fa; padding: 12px; border-radius: 6px; overflow-x: auto; }}
code {{ background: #f0f0f0; padding: 1px 4px; border-radius: 3px; }}
pre code {{ background: none; padding: 0; }}
h1, h2, h3, h4, h5, h6 {{ margin-top: 20px; margin-bottom: 8px; }}
table {{ border-collapse: collapse; width: 100%; margin: 8px 0; }}
th, td {{ border: 1px solid #ddd; padding: 6px 12px; text-align: left; }}
th {{ background: #f5f5f5; font-weight: 600; }}
blockquote {{ border-left: 3px solid #ddd; margin: 8px 0; padding: 4px 12px; color: #555; }}
a {{ color: {accent}; }}
img {{ max-width: 100%; }}\
"""


@dataclass(frozen=True, slots=True)
class _Palette:
    """A single color palette."""

    # Backgrounds
    window_bg: str
    panel_bg: str
    sidebar_bg: str
    input_bg: str
    hover_bg: str
    selected_bg: str

    # Text
    text_primary: str
    text_secondary: str
    accent_text: str

    # Borders / accents
    border: str
    border_light: str
    accent: str
    accent_hover: str
    accent_subtle: str
    button_bg: str
    button_border: str
    button_text: str

    # Status
    status_ok: str
    status_warning: str
    status_error: str
    status_unknown: str

    # Misc
    splitter: str
    header_bg: str


class Theme:
    """Modern theme with blue accent."""

    _LIGHT = _Palette(
        window_bg="#f8f9fa",
        panel_bg="#ffffff",
        sidebar_bg="#f0f1f3",
        input_bg="#ffffff",
        hover_bg="#e9ecef",
        selected_bg="#3b82f6",
        text_primary="#1a1a2e",
        text_secondary="#6b7280",
        accent_text="#ffffff",
        border="#e2e5e9",
        border_light="#f0f1f3",
        accent="#3b82f6",
        accent_hover="#2563eb",
        accent_subtle="#eff6ff",
        button_bg="#ffffff",
        button_border="#d1d5db",
        button_text="#374151",
        status_ok="#059669",
        status_warning="#d97706",
        status_error="#dc2626",
        status_unknown="#9ca3af",
        splitter="#e2e5e9",
        header_bg="#f8f9fa",
    )

    _DARK = _Palette(
        window_bg="#0f1117",
        panel_bg="#1a1d27",
        sidebar_bg="#141620",
        input_bg="#1e2130",
        hover_bg="#262a3a",
        selected_bg="#3b82f6",
        text_primary="#e5e7eb",
        text_secondary="#9ca3af",
        accent_text="#ffffff",
        border="#2d3148",
        border_light="#232738",
        accent="#3b82f6",
        accent_hover="#60a5fa",
        accent_subtle="#1e2a4a",
        button_bg="#232738",
        button_border="#3d4258",
        button_text="#e5e7eb",
        status_ok="#34d399",
        status_warning="#fbbf24",
        status_error="#f87171",
        status_unknown="#6b7280",
        splitter="#2d3148",
        header_bg="#141620",
    )

    def __init__(self, mode: ThemeMode) -> None:
        self.mode = mode
        self._palette = self._LIGHT if mode == ThemeMode.LIGHT else self._DARK

    # ------------------------------------------------------------------ #
    # Convenience accessors
    # ------------------------------------------------------------------ #
    @property
    def window_bg(self) -> str:
        return self._palette.window_bg

    @property
    def panel_bg(self) -> str:
        return self._palette.panel_bg

    @property
    def text_primary(self) -> str:
        return self._palette.text_primary

    @property
    def text_secondary(self) -> str:
        return self._palette.text_secondary

    @property
    def accent(self) -> str:
        return self._palette.accent

    @property
    def sidebar_icon_color(self) -> str:
        """Colour used for inactive sidebar icons."""
        return self._palette.text_secondary

    # ------------------------------------------------------------------ #
    # Stylesheet generation
    # ------------------------------------------------------------------ #
    def stylesheet(self) -> str:
        c = self._palette
        return f"""
        /* ---- Global window ---- */
        QMainWindow {{
            background: {c.window_bg};
            color: {c.text_primary};
            font-family: "Segoe UI", "SF Pro Text", "Inter", sans-serif;
        }}

        QWidget {{
            font-family: "Segoe UI", "SF Pro Text", "Inter", sans-serif;
        }}

        /* ---- Activity bar (sidebar icons) ---- */
        #activityBar {{
            background: {c.sidebar_bg};
            border: none;
            border-right: 1px solid {c.border};
        }}
        QToolButton#activityButton {{
            background: transparent;
            border: none;
            border-radius: 8px;
            padding: 9px;
            color: {c.text_secondary};
        }}
        QToolButton#activityButton:hover {{
            background: {c.hover_bg};
            color: {c.text_primary};
        }}
        QToolButton#activityButton[active="true"] {{
            background: {c.accent_subtle};
            color: {c.accent};
        }}

        /* ---- Panels ---- */
        QFrame#panel {{
            background: {c.panel_bg};
            border: none;
            border-right: 1px solid {c.border_light};
            border-radius: 0;
        }}
        QLabel#panelTitle {{
            color: {c.text_primary};
            font-size: 10pt;
            font-weight: 600;
            letter-spacing: 0.02em;
            text-transform: uppercase;
        }}

        /* ---- FS workspace minimal polish ---- */
        QSplitter#fsWorkspaceSplit::handle {{
            background: {c.border_light};
            width: 4px;
        }}
        QSplitter#fsWorkspaceSplit::handle:hover {{
            background: {c.border};
        }}
        QWidget#dirTreeToolbar,
        QWidget#codeToolbar,
        QWidget#hexToolbar,
        QWidget#imageToolbar {{
            background: transparent;
            border: none;
            border-bottom: 1px solid {c.border_light};
        }}
        QLabel#codePathLabel,
        QLabel#hexPathLabel,
        QLabel#imagePathLabel {{
            color: {c.text_primary};
            font-size: 10pt;
            font-weight: 600;
        }}
        QLabel#hexSizeLabel,
        QLabel#imageSizeLabel {{
            color: {c.text_secondary};
            font-size: 9pt;
        }}
        QLabel#hexReadonlyLabel {{
            color: {c.text_secondary};
            font-size: 8pt;
            font-weight: 700;
            letter-spacing: 0.06em;
            padding: 0 2px;
        }}
        QTreeView#dirTreeView,
        QTextEdit#codeEditor,
        QTextEdit#hexContent,
        QTextBrowser#codePreview,
        QScrollArea#imageScroll {{
            border: none;
            border-radius: 0;
            background: {c.input_bg};
        }}
        QTreeView#dirTreeView::item {{
            padding: 4px 6px;
            margin: 1px 2px;
        }}
        QTreeView#dirTreeView::item:selected {{
            background: {c.hover_bg};
            color: {c.text_primary};
        }}
        QLabel#imageLabel {{
            color: {c.text_secondary};
            font-size: 10pt;
            padding: 18px;
        }}
        QPushButton#openFolderButton,
        QPushButton#codeSaveButton,
        QPushButton#codeMdToggle,
        QPushButton#hexEditToggle,
        QPushButton#hexSaveButton {{
            padding: 6px 12px;
        }}

        /* ---- Settings page typography ---- */
        QFrame#settingsGroup {{
            background: {c.panel_bg};
            border: 1px solid {c.border_light};
            border-radius: 8px;
            padding: 16px;
        }}
        QLabel#settingsGroupTitle {{
            color: {c.text_primary};
            font-size: 10pt;
            font-weight: 600;
            letter-spacing: 0;
        }}
        QLabel#settingsGroupDescription {{
            color: {c.text_secondary};
            font-size: 9pt;
            padding-bottom: 4px;
        }}
        QLabel#settingsFieldLabel {{
            color: {c.text_primary};
            font-weight: 600;
            font-size: 9pt;
        }}
        QLabel#settingsFieldDescription {{
            color: {c.text_secondary};
            font-size: 8pt;
        }}
        QLabel#settingsHint {{
            color: {c.text_secondary};
            font-size: 8pt;
            font-style: italic;
        }}
        QLabel#settingsErrorLabel {{
            color: {c.status_error};
            font-size: 12px;
        }}

        /* ---- Inputs ---- */
        QTreeWidget, QTextEdit, QLineEdit, QListWidget, QSpinBox, QComboBox, QTableWidget {{
            background: {c.input_bg};
            color: {c.text_primary};
            border: 1px solid {c.border};
            border-radius: 6px;
            padding: 6px 8px;
            selection-background-color: {c.accent};
            selection-color: {c.accent_text};
            font-size: 10pt;
        }}
        QLineEdit:focus, QTextEdit:focus, QComboBox:focus, QSpinBox:focus {{
            border: 2px solid {c.accent};
            padding: 5px 7px;
            background: {c.accent_subtle};
        }}
        QLineEdit:read-only {{
            background: {c.border_light};
            color: {c.text_secondary};
        }}

        /* ---- Status cards ---- */
        QFrame#statusCard {{
            background: {c.panel_bg};
            border: none;
            border-top: 1px solid {c.border_light};
            border-left: 4px solid {c.border};
        }}
        QFrame#statusCard[state="ok"] {{
            border-left: 4px solid {c.status_ok};
        }}
        QFrame#statusCard[state="warning"] {{
            border-left: 4px solid {c.status_warning};
        }}
        QFrame#statusCard[state="error"] {{
            border-left: 4px solid {c.status_error};
        }}
        QFrame#statusCard[state="unknown"] {{
            border-left: 4px solid {c.status_unknown};
        }}
        QLabel#statusCardTitle {{
            color: {c.text_primary};
            font-size: 10pt;
            font-weight: 700;
            letter-spacing: 0.01em;
        }}
        QLabel#statusState[state="ok"] {{
            color: {c.status_ok};
            font-weight: 700;
            font-size: 10pt;
        }}
        QLabel#statusState[state="warning"] {{
            color: {c.status_warning};
            font-weight: 700;
            font-size: 10pt;
        }}
        QLabel#statusState[state="error"] {{
            color: {c.status_error};
            font-weight: 700;
            font-size: 10pt;
        }}
        QLabel#statusState[state="unknown"] {{
            color: {c.status_unknown};
            font-weight: 600;
            font-size: 10pt;
        }}

        /* ---- Table header ---- */
        QHeaderView::section {{
            background: {c.header_bg};
            color: {c.text_secondary};
            border: none;
            border-bottom: 1px solid {c.border};
            padding: 8px 6px;
            font-weight: 600;
            font-size: 8pt;
            text-transform: uppercase;
            letter-spacing: 0.04em;
        }}

        /* ---- Buttons ---- */
        QPushButton {{
            background: {c.button_bg};
            color: {c.button_text};
            border: 1px solid {c.button_border};
            border-radius: 6px;
            padding: 8px 16px;
            font-weight: 500;
            font-size: 10pt;
        }}
        QPushButton:hover {{
            background: {c.hover_bg};
            border: 1px solid {c.text_secondary};
        }}
        QPushButton:pressed {{
            background: {c.accent_subtle};
            border: 1px solid {c.accent};
            color: {c.accent};
        }}

        /* Primary action buttons */
        QPushButton#primaryButton {{
            background: {c.accent};
            color: {c.accent_text};
            border: 1px solid {c.accent};
            font-weight: 600;
        }}
        QPushButton#primaryButton:hover {{
            background: {c.accent_hover};
            border: 1px solid {c.accent_hover};
        }}
        QPushButton#primaryButton:pressed {{
            background: {c.text_primary};
            border: 1px solid {c.text_primary};
        }}

        /* ---- Tool buttons (expand toggles) ---- */
        QToolButton {{
            background: transparent;
            color: {c.text_secondary};
            border: 1px solid transparent;
            border-radius: 0;
            font-weight: 600;
            font-size: 9pt;
            padding: 6px 10px;
        }}
        QToolButton:hover {{
            background: {c.hover_bg};
            color: {c.text_primary};
            border: 1px solid {c.border};
        }}
        QToolButton:checked {{
            color: {c.accent};
            background: {c.accent_subtle};
            border: 1px solid {c.accent};
        }}

        /* ---- Menus / category list ---- */
        QMenuBar {{
            background: {c.panel_bg};
            color: {c.text_primary};
            border: none;
            border-bottom: 1px solid {c.border};
            padding: 2px;
        }}
        QMenu {{
            background: {c.panel_bg};
            color: {c.text_primary};
            border: 1px solid {c.border};
            border-radius: 0;
            padding: 4px;
        }}
        QMenuBar::item:selected {{
            background: {c.accent_subtle};
            color: {c.accent};
            border-radius: 0;
        }}
        QMenu::item:selected {{
            background: {c.accent};
            color: {c.accent_text};
            border-radius: 0;
        }}
        QListWidget#settingsCategoryList {{
            background: {c.sidebar_bg};
            color: {c.text_primary};
            border: none;
            border-right: 1px solid {c.border};
            outline: none;
            padding: 8px 4px;
        }}
        QListWidget#settingsCategoryList::item {{
            padding: 10px 12px;
            border-radius: 6px;
            margin: 1px 4px;
            font-weight: 500;
            font-size: 10pt;
        }}
        QListWidget#settingsCategoryList::item:selected {{
            background: {c.accent_subtle};
            color: {c.accent};
            font-weight: 600;
        }}
        QListWidget#settingsCategoryList::item:hover:!selected {{
            background: {c.hover_bg};
        }}

        /* ---- Status bar ---- */
        QStatusBar {{
            background: {c.sidebar_bg};
            color: {c.text_secondary};
            border-top: 1px solid {c.border};
            font-size: 9pt;
            padding: 2px 8px;
        }}

        /* ---- Splitter ---- */
        QSplitter::handle {{
            background: {c.splitter};
            width: 1px;
            height: 1px;
        }}
        QSplitter::handle:hover {{
            background: {c.accent};
        }}

        /* ---- Checkbox ---- */
        QCheckBox {{
            color: {c.text_primary};
            font-size: 9pt;
            spacing: 8px;
        }}
        QCheckBox::indicator {{
            width: 16px;
            height: 16px;
            border: 2px solid {c.border};
            border-radius: 4px;
            background: {c.input_bg};
        }}
        QCheckBox::indicator:hover {{
            border: 2px solid {c.accent};
        }}
        QCheckBox::indicator:checked {{
            background: {c.accent};
            border: 2px solid {c.accent};
            image: none;
        }}

        /* ---- Scroll area ---- */
        QScrollArea {{
            border: none;
            background: transparent;
        }}

        /* ---- Scrollbar ---- */
        QScrollBar:vertical {{
            background: transparent;
            width: 8px;
            margin: 0;
        }}
        QScrollBar::handle:vertical {{
            background: {c.border};
            border-radius: 4px;
            min-height: 30px;
        }}
        QScrollBar::handle:vertical:hover {{
            background: {c.text_secondary};
        }}
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
            height: 0;
        }}
        QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{
            background: none;
        }}

        QScrollBar:horizontal {{
            background: transparent;
            height: 8px;
            margin: 0;
        }}
        QScrollBar::handle:horizontal {{
            background: {c.border};
            border-radius: 4px;
            min-width: 30px;
        }}
        QScrollBar::handle:horizontal:hover {{
            background: {c.text_secondary};
        }}
        QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
            width: 0;
        }}
        QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {{
            background: none;
        }}

        /* ---- Tab bar (QTabBar in QTabWidget) ---- */
        QTabWidget::pane {{
            border: 1px solid {c.border};
            border-radius: 0;
            background: {c.panel_bg};
        }}
        QTabBar::tab {{
            background: transparent;
            color: {c.text_secondary};
            border: none;
            border-bottom: 2px solid transparent;
            padding: 8px 16px;
            font-weight: 500;
            font-size: 10pt;
        }}
        QTabBar::tab:selected {{
            color: {c.accent};
            border-bottom: 2px solid {c.accent};
        }}
        QTabBar::tab:hover:!selected {{
            color: {c.text_primary};
            border-bottom: 2px solid {c.border};
        }}

        /* ---- ToolTip ---- */
        QToolTip {{
            background: {c.panel_bg};
            color: {c.text_primary};
            border: 1px solid {c.border};
            border-radius: 0;
            padding: 6px 10px;
            font-size: 9pt;
        }}

        /* ---- MessageBox ---- */
        QMessageBox {{
            background: {c.panel_bg};
        }}

        /* ---- Card container ---- */
        QFrame#modelProviderCard {{
            background: {c.input_bg};
            border: 1px solid {c.border};
            border-radius: 6px;
        }}
        QFrame#modelProviderCard:hover {{
            border: 1px solid {c.accent};
        }}
        QFrame#modelProviderCard[provider_enabled="true"],
        QFrame#modelProviderCard[server_enabled="true"],
        QFrame#modelProviderCard[skill_enabled="true"] {{
            border-left: 3px solid {c.status_ok};
        }}
        QFrame#modelProviderCard[provider_enabled="true"]:hover,
        QFrame#modelProviderCard[server_enabled="true"]:hover,
        QFrame#modelProviderCard[skill_enabled="true"]:hover {{
            border-left: 3px solid {c.status_ok};
        }}
        QFrame#modelProviderCard[provider_enabled="false"],
        QFrame#modelProviderCard[server_enabled="false"],
        QFrame#modelProviderCard[skill_enabled="false"] {{
            border-left: 3px solid {c.border};
        }}

        /* ---- Card badges (pill tags) ---- */
        QLabel#cardBadgeEnabled {{
            color: {c.status_ok};
            font-size: 8pt;
            font-weight: 600;
            padding: 2px 8px;
            border-radius: 10px;
            background: {c.status_ok}18;
        }}
        QLabel#cardBadgeDisabled {{
            color: {c.status_unknown};
            font-size: 8pt;
            font-weight: 600;
            padding: 2px 8px;
            border-radius: 10px;
            background: {c.status_unknown}18;
        }}
        QLabel#cardBadgeTransport {{
            color: {c.accent};
            font-size: 8pt;
            font-weight: 600;
            padding: 2px 8px;
            border-radius: 10px;
            background: {c.accent}18;
        }}
        QLabel#cardBadgeVersion {{
            color: {c.text_secondary};
            font-size: 8pt;
            font-weight: 500;
            padding: 2px 8px;
            border-radius: 10px;
            background: {c.border_light};
        }}

        /* ---- Card toggle button ---- */
        QPushButton#cardToggleButton {{
            background: {c.accent};
            color: {c.accent_text};
            border: 1px solid {c.accent};
            border-radius: 4px;
            padding: 2px 12px;
            font-size: 8pt;
            font-weight: 600;
        }}
        QPushButton#cardToggleButton:hover {{
            background: {c.accent_hover};
            border: 1px solid {c.accent_hover};
        }}
        QPushButton#cardToggleButton[active="false"] {{
            background: transparent;
            color: {c.text_secondary};
            border: 1px solid {c.border};
        }}
        QPushButton#cardToggleButton[active="false"]:hover {{
            background: {c.hover_bg};
            border: 1px solid {c.text_secondary};
        }}

        /* ---- Card edit button ---- */
        QPushButton#modelCardEditButton {{
            background: transparent;
            color: {c.text_secondary};
            border: 1px solid {c.border};
            border-radius: 4px;
            padding: 2px 10px;
            font-size: 9pt;
        }}
        QPushButton#modelCardEditButton:hover {{
            background: {c.hover_bg};
            color: {c.text_primary};
            border: 1px solid {c.text_secondary};
        }}

        /* ---- Danger button (theme-aware) ---- */
        QPushButton#dangerButton {{
            background: transparent;
            color: {c.status_error};
            border: 1px solid transparent;
            border-radius: 4px;
            padding: 2px 8px;
            font-size: 9pt;
        }}
        QPushButton#dangerButton:hover {{
            background: {c.status_error}1a;
            border: 1px solid {c.status_error};
        }}

        /* ---- Card detail separator ---- */
        QFrame#cardSeparator {{
            background: {c.border_light};
            max-height: 1px;
        }}

        /* ---- Model provider / MCP server dialog ---- */
        QDialog#modelProviderDialog,
        QDialog#mcpServerDialog {{
            background: {c.panel_bg};
        }}
        QLabel#dialogSectionTitle {{
            color: {c.text_primary};
            font-size: 10pt;
            font-weight: 700;
            padding-top: 8px;
        }}
        QFrame#dialogSeparator {{
            background: {c.border_light};
            max-height: 1px;
        }}

        /* ---- Chat page ---- */
        QFrame#chatComposerContainer {{
            background: {c.input_bg};
            border: 1px solid {c.border};
            border-radius: 16px;
        }}
        QFrame#chatBubbleUser {{
            background: {c.accent};
            color: {c.accent_text};
            border-radius: 12px;
            border: none;
            margin-left: 48px;
        }}
        QFrame#chatBubbleAssistant {{
            background: {c.input_bg};
            color: {c.text_primary};
            border-radius: 12px;
            border: 1px solid {c.border_light};
            margin-right: 48px;
        }}
        QLabel#chatBubbleText {{
            font-size: 10pt;
        }}
        QFrame#toolTraceCard {{
            background: {c.border_light};
            border: 1px solid {c.border};
            border-radius: 8px;
            margin-left: 24px;
            margin-right: 24px;
        }}
        QLabel#toolTraceTool {{
            color: {c.text_secondary};
            font-size: 9pt;
            font-weight: 600;
        }}
        QLabel#toolTraceStatus {{
            color: {c.text_secondary};
            font-size: 8pt;
        }}
        QTextEdit#chatInput {{
            background: transparent;
            color: {c.text_primary};
            border: none;
            border-radius: 12px;
            padding: 6px 8px;
            font-size: 10pt;
        }}
        QTextEdit#chatInput:focus {{
            background: transparent;
        }}
        QTextEdit#chatInput:disabled {{
            color: {c.text_secondary};
        }}
        QPushButton#chatModelButton {{
            background: transparent;
            color: {c.text_secondary};
            border: none;
            border-radius: 12px;
            padding: 4px 12px;
            font-size: 9pt;
            font-weight: 500;
            text-align: left;
        }}
        QPushButton#chatModelButton:hover {{
            background: {c.accent_subtle};
            color: {c.accent};
        }}
        QPushButton#chatSendRoundButton {{
            background: {c.accent};
            color: {c.accent_text};
            border: none;
            border-radius: 16px;
            font-size: 14pt;
            font-weight: bold;
            padding: 0px;
        }}
        QPushButton#chatSendRoundButton:hover {{
            background: {c.accent_hover};
        }}
        QPushButton#chatSendRoundButton:disabled {{
            background: {c.border_light};
            color: {c.text_secondary};
        }}
        QMenu#chatModelMenu {{
            background: {c.panel_bg};
            border: 1px solid {c.border};
            border-radius: 8px;
            padding: 4px;
        }}
        QMenu#chatModelMenu::item {{
            padding: 6px 20px;
            border-radius: 4px;
            color: {c.text_primary};
        }}
        QMenu#chatModelMenu::item:selected {{
            background: {c.accent_subtle};
            color: {c.accent};
        }}
        QMenu#chatModelMenu::item:checked {{
            background: {c.accent_subtle};
            color: {c.accent};
            font-weight: 600;
        }}
        QMenu#chatModelMenu::indicator {{
            width: 8px;
            height: 8px;
            border-radius: 4px;
            background: {c.accent};
            margin-left: 4px;
        }}
        """

    @classmethod
    def light(cls) -> "Theme":
        return cls(ThemeMode.LIGHT)

    @classmethod
    def dark(cls) -> "Theme":
        return cls(ThemeMode.DARK)
