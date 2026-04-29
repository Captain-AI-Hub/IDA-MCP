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

# Legacy font constants (kept for backward compat; prefer _Metrics)
FONT_FAMILY = '"Segoe UI", "SF Pro Text", "Inter", sans-serif'
MONO_FONT_FAMILY = '"Cascadia Code", "Consolas", monospace'
MONO_FONT_SIZE = 10


def mono_font() -> QFont:
    """Return the application-wide monospace font."""
    return QFont("Cascadia Code", MONO_FONT_SIZE)


# -----------------------------------------------------------------------
# Syntax highlighting tokens
# -----------------------------------------------------------------------

SYNTAX_TOKENS_LIGHT: dict[str, tuple[str, bool]] = {
    # token suffix -> (hex colour, bold)
    "Token.Comment":       ("#008000", False),
    "Token.Keyword":       ("#7C3AED", True),
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

SYNTAX_TOKENS_DARK: dict[str, tuple[str, bool]] = {
    "Token.Comment":       ("#6A9955", False),
    "Token.Keyword":       ("#C586C0", True),
    "Token.Literal.String": ("#CE9178", False),
    "Token.Literal.Number": ("#B5CEA8", False),
    "Token.Name.Builtin":  ("#4EC9B0", False),
    "Token.Name.Function": ("#DCDCAA", False),
    "Token.Name.Class":    ("#4EC9B0", True),
    "Token.Name.Decorator": ("#DCDCAA", False),
    "Token.Name.Attribute": ("#9CDCFE", False),
    "Token.Operator":      ("#D4D4D4", False),
    "Token.Name.Variable": ("#9CDCFE", False),
}

# Keep legacy alias for backwards compat
SYNTAX_TOKENS = SYNTAX_TOKENS_LIGHT


def current_theme_mode() -> str:
    """Return the active theme mode string ("light" or "dark").

    Walks all top-level windows to find the MainWindow so that modal
    dialogs (which become activeWindow) do not cause incorrect lookups.
    Falls back to "light" if no window is available.
    """
    try:
        from PySide6.QtWidgets import QApplication, QMainWindow

        app = QApplication.instance()
        if app:
            for w in app.topLevelWidgets():
                if isinstance(w, QMainWindow) and hasattr(w, "_theme_mode"):
                    return getattr(w, "_theme_mode", "light")
            # Fallback to activeWindow for non-MainWindow cases
            mw = app.activeWindow()
            return getattr(mw, "_theme_mode", "light") if mw else "light"
    except Exception:
        pass
    return "light"


def current_theme_mode_enum() -> ThemeMode:
    """Return the active ThemeMode enum value."""
    return ThemeMode.DARK if current_theme_mode() == "dark" else ThemeMode.LIGHT


def current_palette() -> _Palette:
    """Return the palette for the current theme mode."""
    return Theme(current_theme_mode_enum())._palette


def apply_app_palette(mode: ThemeMode | None = None) -> None:
    """Set the QApplication palette so widgets without QSS rules
    fall back to the theme colours instead of the system palette."""
    try:
        from PySide6.QtWidgets import QApplication
        from PySide6.QtGui import QPalette, QColor

        app = QApplication.instance()
        if app is None:
            return

        if mode is None:
            mode = current_theme_mode_enum()
        c = Theme(mode)._palette

        palette = QPalette()
        palette.setColor(QPalette.ColorRole.Window, QColor(c.window_bg))
        palette.setColor(QPalette.ColorRole.WindowText, QColor(c.text_primary))
        palette.setColor(QPalette.ColorRole.Base, QColor(c.input_bg))
        palette.setColor(QPalette.ColorRole.AlternateBase, QColor(c.panel_bg))
        palette.setColor(QPalette.ColorRole.Text, QColor(c.text_primary))
        palette.setColor(QPalette.ColorRole.PlaceholderText, QColor(c.text_secondary))
        palette.setColor(QPalette.ColorRole.Button, QColor(c.button_bg))
        palette.setColor(QPalette.ColorRole.ButtonText, QColor(c.button_text))
        palette.setColor(QPalette.ColorRole.Highlight, QColor(c.accent))
        palette.setColor(QPalette.ColorRole.HighlightedText, QColor(c.accent_text))
        palette.setColor(QPalette.ColorRole.ToolTipBase, QColor(c.panel_bg))
        palette.setColor(QPalette.ColorRole.ToolTipText, QColor(c.text_primary))
        app.setPalette(palette)
    except Exception:
        pass


def syntax_tokens(mode: ThemeMode | None = None) -> dict[str, tuple[str, bool]]:
    """Return syntax tokens for the given mode (light default)."""
    if mode == ThemeMode.DARK:
        return SYNTAX_TOKENS_DARK
    return SYNTAX_TOKENS_LIGHT


def markdown_css(palette: _Palette | None = None, metrics: _Metrics | None = None) -> str:
    """Return the CSS string used inside the markdown preview HTML template.

    Accepts a palette and metrics so colours and sizes adapt to light/dark
    mode automatically.
    """
    if palette is None:
        palette = Theme._LIGHT
    if metrics is None:
        metrics = _DEFAULT_METRICS
    c = palette
    m = metrics
    return f"""\
body {{ font-family: {m.font_family}; font-size: {m.font_size_md}; color: {c.text_primary}; margin: 0; }}
pre, code {{ font-family: {m.mono_family}; }}
pre {{ font-size: 13px; background: {c.sidebar_bg}; color: {c.text_primary}; padding: {m.spacing_lg}; border: 1px solid {c.border}; border-radius: {m.radius_md}; overflow-x: auto; }}
code {{ background: {c.sidebar_bg}; color: {c.text_primary}; padding: 1px {m.spacing_xs}; border-radius: {m.radius_xs}; }}
pre code {{ background: none; padding: 0; border: none; }}
h1, h2, h3, h4, h5, h6 {{ margin-top: {m.spacing_3xl}; margin-bottom: {m.spacing_md}; color: {c.accent}; }}
table {{ border-collapse: collapse; width: 100%; margin: {m.spacing_md} 0; }}
th, td {{ border: 1px solid {c.border}; padding: {m.spacing_sm} {m.spacing_lg}; text-align: left; }}
th {{ background: {c.sidebar_bg}; font-weight: {m.font_weight_semibold}; }}
blockquote {{ border-left: 3px solid {c.border}; margin: {m.spacing_md} 0; padding: {m.spacing_xs} {m.spacing_lg}; color: {c.text_secondary}; }}
a {{ color: {c.accent}; }}
img {{ max-width: 100%; }}\
"""


# -----------------------------------------------------------------------
# Design metrics: non-colour UI tokens
# -----------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class _Metrics:
    """Design tokens for UI metrics (sizes, spacing, fonts)."""

    # Fonts
    font_family: str = '"Segoe UI", "SF Pro Text", "Inter", sans-serif'
    mono_family: str = '"Cascadia Code", "Consolas", monospace'
    font_size_base: str = "10pt"
    font_size_sm: str = "9pt"
    font_size_xs: str = "8pt"
    font_size_md: str = "12px"
    font_size_lg: str = "14pt"

    # Border radius
    radius_xs: str = "3px"
    radius_sm: str = "4px"
    radius_md: str = "6px"
    radius_lg: str = "8px"
    radius_xl: str = "12px"
    radius_round: str = "16px"
    radius_pill: str = "10px"

    # Spacing
    spacing_xxs: str = "2px"
    spacing_xs: str = "4px"
    spacing_sm: str = "6px"
    spacing_md: str = "8px"
    spacing_lg: str = "12px"
    spacing_xl: str = "16px"
    spacing_2xl: str = "18px"
    spacing_3xl: str = "20px"
    spacing_4xl: str = "24px"

    # Typography
    letter_spacing_tight: str = "0.01em"
    letter_spacing_normal: str = "0.02em"
    letter_spacing_wide: str = "0.04em"
    letter_spacing_xwide: str = "0.06em"
    line_height_normal: str = "1.5"
    font_weight_medium: str = "500"
    font_weight_semibold: str = "600"
    font_weight_bold: str = "700"


_DEFAULT_METRICS = _Metrics()


# -----------------------------------------------------------------------
# Colour palette
# -----------------------------------------------------------------------

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

    def __init__(self, mode: ThemeMode, metrics: _Metrics | None = None) -> None:
        self.mode = mode
        self._palette = self._LIGHT if mode == ThemeMode.LIGHT else self._DARK
        self._metrics = metrics or _DEFAULT_METRICS

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
    # Stylesheet generation — per-component methods
    # ------------------------------------------------------------------ #
    def stylesheet(self) -> str:
        c = self._palette
        m = self._metrics
        return "\n".join([
            self._global_styles(c, m),
            self._sidebar_styles(c, m),
            self._panel_styles(c, m),
            self._workspace_styles(c, m),
            self._settings_styles(c, m),
            self._input_styles(c, m),
            self._status_card_styles(c, m),
            self._table_styles(c, m),
            self._button_styles(c, m),
            self._primary_button_styles(c, m),
            self._tool_button_styles(c, m),
            self._menu_styles(c, m),
            self._statusbar_styles(c, m),
            self._splitter_styles(c, m),
            self._checkbox_styles(c, m),
            self._scrollarea_styles(c, m),
            self._scrollbar_styles(c, m),
            self._tab_styles(c, m),
            self._tooltip_styles(c, m),
            self._messagebox_styles(c, m),
            self._card_container_styles(c, m),
            self._card_badge_styles(c, m),
            self._card_toggle_styles(c, m),
            self._card_edit_styles(c, m),
            self._danger_button_styles(c, m),
            self._card_separator_styles(c, m),
            self._dialog_styles(c, m),
            self._chat_layout_styles(c, m),
            self._chat_role_styles(c, m),
            self._chat_thinking_styles(c, m),
            self._tool_trace_card_styles(c, m),
            self._tool_call_styles(c, m),
            self._chat_input_styles(c, m),
            self._chat_button_styles(c, m),
            self._chat_menu_styles(c, m),
            self._session_sidebar_styles(c, m),
            self._skill_card_styles(c, m),
            self._chat_skill_styles(c, m),
            self._chat_markdown_styles(c, m),
            self._tool_trace_panel_styles(c, m),
            self._advanced_toggle_styles(c, m),
            self._skill_prompt_styles(c, m),
            self._scroll_container_styles(c, m),
            self._provider_menu_styles(c, m),
        ])

    # -- Global --

    @staticmethod
    def _global_styles(c: _Palette, m: _Metrics) -> str:
        return f"""
        /* ---- Global window ---- */
        QMainWindow {{
            background: {c.window_bg};
            color: {c.text_primary};
            font-family: {m.font_family};
        }}

        QWidget {{
            font-family: {m.font_family};
            color: {c.text_primary};
            font-size: {m.font_size_base};
        }}

        /* ---- Generic labels ---- */
        QLabel {{
            color: {c.text_primary};
        }}

        /* ---- Page stack (right-side content) ---- */
        QStackedWidget#pageStack {{
            background: {c.window_bg};
        }}

        /* ---- Chat page ---- */
        QWidget#chatPage {{
            background: {c.panel_bg};
        }}

        /* ---- Message list area ---- */
        QWidget#messageListArea {{
            background: {c.panel_bg};
        }}

        /* ---- Composer area ---- */
        QWidget#composerArea {{
            background: {c.panel_bg};
        }}

        /* ---- Settings body ---- */
        QWidget#settingsBody {{
            background: {c.window_bg};
        }}

        /* ---- Settings stack (right-side pages) ---- */
        QStackedWidget#settingsStack {{
            background: {c.window_bg};
        }}

        /* ---- Settings page content (inside scroll area) ---- */
        QWidget#settingsPageContent {{
            background: {c.window_bg};
        }}

        /* ---- Status content ---- */
        QWidget#statusContent {{
            background: {c.window_bg};
        }}"""

    # -- Activity bar --

    @staticmethod
    def _sidebar_styles(c: _Palette, m: _Metrics) -> str:
        return f"""
        /* ---- Activity bar (sidebar icons) ---- */
        #activityBar {{
            background: {c.sidebar_bg};
            border: none;
            border-right: 1px solid {c.border};
        }}
        QToolButton#activityButton {{
            background: transparent;
            border: none;
            border-radius: {m.radius_lg};
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
        }}"""

    # -- Panels --

    @staticmethod
    def _panel_styles(c: _Palette, m: _Metrics) -> str:
        return f"""
        /* ---- Panels ---- */
        QFrame#panel {{
            background: {c.panel_bg};
            border: none;
            border-right: 1px solid {c.border_light};
            border-radius: 0;
        }}
        QLabel#panelTitle {{
            color: {c.text_primary};
            font-size: {m.font_size_base};
            font-weight: {m.font_weight_semibold};
            letter-spacing: {m.letter_spacing_normal};
            text-transform: uppercase;
        }}"""

    # -- FS workspace --

    @staticmethod
    def _workspace_styles(c: _Palette, m: _Metrics) -> str:
        return f"""
        /* ---- FS workspace minimal polish ---- */
        QSplitter#fsWorkspaceSplit::handle {{
            background: {c.border_light};
            width: {m.spacing_xs};
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
            font-size: {m.font_size_base};
            font-weight: {m.font_weight_semibold};
        }}
        QLabel#hexSizeLabel,
        QLabel#imageSizeLabel {{
            color: {c.text_secondary};
            font-size: {m.font_size_sm};
        }}
        QLabel#hexReadonlyLabel {{
            color: {c.text_secondary};
            font-size: {m.font_size_xs};
            font-weight: {m.font_weight_bold};
            letter-spacing: {m.letter_spacing_xwide};
            padding: 0 {m.spacing_xxs};
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
            padding: {m.spacing_xs} {m.spacing_sm};
            margin: 1px {m.spacing_xs};
        }}
        QTreeView#dirTreeView::item:selected {{
            background: {c.hover_bg};
            color: {c.text_primary};
        }}
        QLabel#imageLabel {{
            color: {c.text_secondary};
            font-size: {m.font_size_base};
            padding: {m.spacing_2xl};
        }}
        QPushButton#openFolderButton,
        QPushButton#codeSaveButton,
        QPushButton#codeMdToggle,
        QPushButton#hexEditToggle,
        QPushButton#hexSaveButton {{
            padding: {m.spacing_sm} {m.spacing_lg};
        }}"""

    # -- Settings page typography --

    @staticmethod
    def _settings_styles(c: _Palette, m: _Metrics) -> str:
        return f"""
        /* ---- Settings page typography ---- */
        QFrame#settingsGroup {{
            background: {c.panel_bg};
            border: 1px solid {c.border_light};
            border-radius: {m.radius_lg};
            padding: {m.spacing_xl};
        }}
        QLabel#settingsGroupTitle {{
            color: {c.text_primary};
            font-size: {m.font_size_base};
            font-weight: {m.font_weight_semibold};
            letter-spacing: 0;
        }}
        QLabel#settingsGroupDescription {{
            color: {c.text_secondary};
            font-size: {m.font_size_sm};
            padding-bottom: {m.spacing_xs};
        }}
        QLabel#settingsFieldLabel {{
            color: {c.text_primary};
            font-weight: {m.font_weight_semibold};
            font-size: {m.font_size_sm};
        }}
        QLabel#settingsFieldDescription {{
            color: {c.text_secondary};
            font-size: {m.font_size_xs};
        }}
        QLabel#settingsHint {{
            color: {c.text_secondary};
            font-size: {m.font_size_xs};
            font-style: italic;
        }}
        QLabel#settingsErrorLabel {{
            color: {c.status_error};
            font-size: {m.font_size_md};
        }}"""

    # -- Inputs --

    @staticmethod
    def _input_styles(c: _Palette, m: _Metrics) -> str:
        return f"""
        /* ---- Inputs ---- */
        QTreeWidget, QTextEdit, QLineEdit, QListWidget, QSpinBox, QDoubleSpinBox, QComboBox, QTableWidget {{
            background: {c.input_bg};
            color: {c.text_primary};
            border: 1px solid {c.border};
            border-radius: {m.radius_md};
            padding: {m.spacing_sm} {m.spacing_md};
            selection-background-color: {c.accent};
            selection-color: {c.accent_text};
            font-size: {m.font_size_base};
        }}
        QLineEdit:focus, QTextEdit:focus, QComboBox:focus, QSpinBox:focus, QDoubleSpinBox:focus {{
            border: 2px solid {c.accent};
            padding: 5px 7px;
            background: {c.accent_subtle};
        }}
        QComboBox QAbstractItemView {{
            background: {c.input_bg};
            color: {c.text_primary};
            border: 1px solid {c.border};
            selection-background-color: {c.accent};
            selection-color: {c.accent_text};
            min-height: 150px;
        }}
        QComboBox::drop-down {{
            background: transparent;
            border: none;
            width: 20px;
        }}
        QLineEdit:read-only {{
            background: {c.border_light};
            color: {c.text_secondary};
        }}"""

    # -- Status cards --

    @staticmethod
    def _status_card_styles(c: _Palette, m: _Metrics) -> str:
        return f"""
        /* ---- Status cards ---- */
        QFrame#statusCard {{
            background: {c.panel_bg};
            border: none;
            border-top: 1px solid {c.border_light};
            border-left: {m.spacing_xs} solid {c.border};
        }}
        QFrame#statusCard[state="ok"] {{
            border-left: {m.spacing_xs} solid {c.status_ok};
        }}
        QFrame#statusCard[state="warning"] {{
            border-left: {m.spacing_xs} solid {c.status_warning};
        }}
        QFrame#statusCard[state="error"] {{
            border-left: {m.spacing_xs} solid {c.status_error};
        }}
        QFrame#statusCard[state="unknown"] {{
            border-left: {m.spacing_xs} solid {c.status_unknown};
        }}
        QLabel#statusCardTitle {{
            color: {c.text_primary};
            font-size: {m.font_size_base};
            font-weight: {m.font_weight_bold};
            letter-spacing: {m.letter_spacing_tight};
        }}
        QLabel#statusState[state="ok"] {{
            color: {c.status_ok};
            font-weight: {m.font_weight_bold};
            font-size: {m.font_size_base};
        }}
        QLabel#statusState[state="warning"] {{
            color: {c.status_warning};
            font-weight: {m.font_weight_bold};
            font-size: {m.font_size_base};
        }}
        QLabel#statusState[state="error"] {{
            color: {c.status_error};
            font-weight: {m.font_weight_bold};
            font-size: {m.font_size_base};
        }}
        QLabel#statusState[state="unknown"] {{
            color: {c.status_unknown};
            font-weight: {m.font_weight_semibold};
            font-size: {m.font_size_base};
        }}"""

    # -- Table header --

    @staticmethod
    def _table_styles(c: _Palette, m: _Metrics) -> str:
        return f"""
        /* ---- Table header ---- */
        QHeaderView::section {{
            background: {c.header_bg};
            color: {c.text_secondary};
            border: none;
            border-bottom: 1px solid {c.border};
            padding: {m.spacing_md} {m.spacing_sm};
            font-weight: {m.font_weight_semibold};
            font-size: {m.font_size_xs};
            text-transform: uppercase;
            letter-spacing: {m.letter_spacing_wide};
        }}"""

    # -- Buttons --

    @staticmethod
    def _button_styles(c: _Palette, m: _Metrics) -> str:
        return f"""
        /* ---- Buttons ---- */
        QPushButton {{
            background: {c.button_bg};
            color: {c.button_text};
            border: 1px solid {c.button_border};
            border-radius: {m.radius_md};
            padding: {m.spacing_md} {m.spacing_xl};
            font-weight: {m.font_weight_medium};
            font-size: {m.font_size_base};
        }}
        QPushButton:hover {{
            background: {c.hover_bg};
            border: 1px solid {c.text_secondary};
        }}
        QPushButton:pressed {{
            background: {c.accent_subtle};
            border: 1px solid {c.accent};
            color: {c.accent};
        }}"""

    @staticmethod
    def _primary_button_styles(c: _Palette, m: _Metrics) -> str:
        return f"""
        /* Primary action buttons */
        QPushButton#primaryButton {{
            background: {c.accent};
            color: {c.accent_text};
            border: 1px solid {c.accent};
            font-weight: {m.font_weight_semibold};
        }}
        QPushButton#primaryButton:hover {{
            background: {c.accent_hover};
            border: 1px solid {c.accent_hover};
        }}
        QPushButton#primaryButton:pressed {{
            background: {c.text_primary};
            border: 1px solid {c.text_primary};
        }}"""

    # -- Tool buttons --

    @staticmethod
    def _tool_button_styles(c: _Palette, m: _Metrics) -> str:
        return f"""
        /* ---- Tool buttons (expand toggles) ---- */
        QToolButton {{
            background: transparent;
            color: {c.text_secondary};
            border: 1px solid transparent;
            border-radius: 0;
            font-weight: {m.font_weight_semibold};
            font-size: {m.font_size_sm};
            padding: {m.spacing_sm} 10px;
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
        }}"""

    # -- Menus / category list --

    @staticmethod
    def _menu_styles(c: _Palette, m: _Metrics) -> str:
        return f"""
        /* ---- Menus / category list ---- */
        QMenuBar {{
            background: {c.panel_bg};
            color: {c.text_primary};
            border: none;
            border-bottom: 1px solid {c.border};
            padding: {m.spacing_xxs};
        }}
        QMenu {{
            background: {c.panel_bg};
            color: {c.text_primary};
            border: 1px solid {c.border};
            border-radius: 0;
            padding: {m.spacing_xs};
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
            padding: {m.spacing_md} {m.spacing_xs};
        }}
        QListWidget#settingsCategoryList::item {{
            padding: {m.spacing_md} {m.spacing_lg};
            border-radius: {m.radius_md};
            margin: 1px {m.spacing_xs};
            font-weight: {m.font_weight_medium};
            font-size: {m.font_size_base};
        }}
        QListWidget#settingsCategoryList::item:selected {{
            background: {c.accent_subtle};
            color: {c.accent};
            font-weight: {m.font_weight_semibold};
        }}
        QListWidget#settingsCategoryList::item:hover:!selected {{
            background: {c.hover_bg};
        }}"""

    # -- Status bar --

    @staticmethod
    def _statusbar_styles(c: _Palette, m: _Metrics) -> str:
        return f"""
        /* ---- Status bar ---- */
        QStatusBar {{
            background: {c.sidebar_bg};
            color: {c.text_secondary};
            border-top: 1px solid {c.border};
            font-size: {m.font_size_sm};
            padding: {m.spacing_xxs} {m.spacing_md};
        }}"""

    # -- Splitter --

    @staticmethod
    def _splitter_styles(c: _Palette, m: _Metrics) -> str:  # noqa: ARG004
        return f"""
        /* ---- Splitter ---- */
        QSplitter::handle {{
            background: {c.splitter};
            width: 1px;
            height: 1px;
        }}
        QSplitter::handle:hover {{
            background: {c.accent};
        }}"""

    # -- Checkbox --

    @staticmethod
    def _checkbox_styles(c: _Palette, m: _Metrics) -> str:
        return f"""
        /* ---- Checkbox ---- */
        QCheckBox {{
            color: {c.text_primary};
            font-size: {m.font_size_sm};
            spacing: {m.spacing_md};
        }}
        QCheckBox::indicator {{
            width: {m.spacing_xl};
            height: {m.spacing_xl};
            border: {m.spacing_xxs} solid {c.border};
            border-radius: {m.radius_sm};
            background: {c.input_bg};
        }}
        QCheckBox::indicator:hover {{
            border: {m.spacing_xxs} solid {c.accent};
        }}
        QCheckBox::indicator:checked {{
            background: {c.accent};
            border: {m.spacing_xxs} solid {c.accent};
            image: none;
        }}"""

    # -- Scroll area --

    @staticmethod
    def _scrollarea_styles(c: _Palette, m: _Metrics) -> str:  # noqa: ARG004
        return f"""
        /* ---- Scroll area ---- */
        QScrollArea {{
            border: none;
            background: transparent;
        }}
        QScrollArea#settingsScrollArea,
        QScrollArea#settingsScrollArea::viewport {{
            background: {c.window_bg};
        }}"""

    # -- Scrollbar --

    @staticmethod
    def _scrollbar_styles(c: _Palette, m: _Metrics) -> str:
        return f"""
        /* ---- Scrollbar ---- */
        QScrollBar:vertical {{
            background: transparent;
            width: {m.spacing_md};
            margin: 0;
        }}
        QScrollBar::handle:vertical {{
            background: {c.border};
            border-radius: {m.radius_sm};
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
            height: {m.spacing_md};
            margin: 0;
        }}
        QScrollBar::handle:horizontal {{
            background: {c.border};
            border-radius: {m.radius_sm};
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
        }}"""

    # -- Tab bar --

    @staticmethod
    def _tab_styles(c: _Palette, m: _Metrics) -> str:
        return f"""
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
            border-bottom: {m.spacing_xxs} solid transparent;
            padding: {m.spacing_md} {m.spacing_xl};
            font-weight: {m.font_weight_medium};
            font-size: {m.font_size_base};
        }}
        QTabBar::tab:selected {{
            color: {c.accent};
            border-bottom: {m.spacing_xxs} solid {c.accent};
        }}
        QTabBar::tab:hover:!selected {{
            color: {c.text_primary};
            border-bottom: {m.spacing_xxs} solid {c.border};
        }}"""

    # -- ToolTip --

    @staticmethod
    def _tooltip_styles(c: _Palette, m: _Metrics) -> str:
        return f"""
        /* ---- ToolTip ---- */
        QToolTip {{
            background: {c.panel_bg};
            color: {c.text_primary};
            border: 1px solid {c.border};
            border-radius: 0;
            padding: {m.spacing_sm} 10px;
            font-size: {m.font_size_sm};
        }}"""

    # -- MessageBox --

    @staticmethod
    def _messagebox_styles(c: _Palette, m: _Metrics) -> str:  # noqa: ARG004
        return f"""
        /* ---- MessageBox ---- */
        QMessageBox {{
            background: {c.panel_bg};
        }}"""

    # -- Card container --

    @staticmethod
    def _card_container_styles(c: _Palette, m: _Metrics) -> str:
        return f"""
        /* ---- Card container ---- */
        QFrame#modelProviderCard {{
            background: {c.input_bg};
            border: 1px solid {c.border};
            border-radius: {m.radius_md};
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
        }}"""

    # -- Card badges --

    @staticmethod
    def _card_badge_styles(c: _Palette, m: _Metrics) -> str:
        return f"""
        /* ---- Card badges (pill tags) ---- */
        QLabel#cardBadgeEnabled {{
            color: {c.status_ok};
            font-size: {m.font_size_xs};
            font-weight: {m.font_weight_semibold};
            padding: {m.spacing_xxs} {m.spacing_md};
            border-radius: {m.radius_pill};
            background: {c.status_ok}18;
        }}
        QLabel#cardBadgeDisabled {{
            color: {c.status_unknown};
            font-size: {m.font_size_xs};
            font-weight: {m.font_weight_semibold};
            padding: {m.spacing_xxs} {m.spacing_md};
            border-radius: {m.radius_pill};
            background: {c.status_unknown}18;
        }}
        QLabel#cardBadgeTransport {{
            color: {c.accent};
            font-size: {m.font_size_xs};
            font-weight: {m.font_weight_semibold};
            padding: {m.spacing_xxs} {m.spacing_md};
            border-radius: {m.radius_pill};
            background: {c.accent}18;
        }}
        QLabel#cardBadgeVersion {{
            color: {c.text_secondary};
            font-size: {m.font_size_xs};
            font-weight: {m.font_weight_medium};
            padding: {m.spacing_xxs} {m.spacing_md};
            border-radius: {m.radius_pill};
            background: {c.border_light};
        }}"""

    # -- Card toggle button --

    @staticmethod
    def _card_toggle_styles(c: _Palette, m: _Metrics) -> str:
        return f"""
        /* ---- Card toggle button ---- */
        QPushButton#cardToggleButton {{
            background: {c.accent};
            color: {c.accent_text};
            border: 1px solid {c.accent};
            border-radius: {m.radius_sm};
            padding: {m.spacing_xxs} {m.spacing_lg};
            font-size: {m.font_size_xs};
            font-weight: {m.font_weight_semibold};
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
        }}"""

    # -- Card edit button --

    @staticmethod
    def _card_edit_styles(c: _Palette, m: _Metrics) -> str:
        return f"""
        /* ---- Card edit button ---- */
        QPushButton#modelCardEditButton {{
            background: transparent;
            color: {c.text_secondary};
            border: 1px solid {c.border};
            border-radius: {m.radius_sm};
            padding: {m.spacing_xxs} 10px;
            font-size: {m.font_size_sm};
        }}
        QPushButton#modelCardEditButton:hover {{
            background: {c.hover_bg};
            color: {c.text_primary};
            border: 1px solid {c.text_secondary};
        }}"""

    # -- Danger button --

    @staticmethod
    def _danger_button_styles(c: _Palette, m: _Metrics) -> str:
        return f"""
        /* ---- Danger button (theme-aware) ---- */
        QPushButton#dangerButton {{
            background: transparent;
            color: {c.status_error};
            border: 1px solid transparent;
            border-radius: {m.radius_sm};
            padding: {m.spacing_xxs} {m.spacing_md};
            font-size: {m.font_size_sm};
        }}
        QPushButton#dangerButton:hover {{
            background: {c.status_error}1a;
            border: 1px solid {c.status_error};
        }}"""

    # -- Card detail separator --

    @staticmethod
    def _card_separator_styles(c: _Palette, m: _Metrics) -> str:  # noqa: ARG004
        return f"""
        /* ---- Card detail separator ---- */
        QFrame#cardSeparator {{
            background: {c.border_light};
            max-height: 1px;
        }}"""

    # -- Model provider / MCP server dialog --

    @staticmethod
    def _dialog_styles(c: _Palette, m: _Metrics) -> str:
        return f"""
        /* ---- Model provider / MCP server dialog ---- */
        QDialog#modelProviderDialog,
        QDialog#mcpServerDialog,
        QDialog#mcpServerDetailDialog {{
            background: {c.panel_bg};
        }}
        QLabel#dialogSectionTitle {{
            color: {c.text_primary};
            font-size: {m.font_size_base};
            font-weight: {m.font_weight_bold};
            padding-top: {m.spacing_md};
        }}
        QFrame#dialogSeparator {{
            background: {c.border_light};
            max-height: 1px;
        }}"""

    # -- Chat layout --

    @staticmethod
    def _chat_layout_styles(c: _Palette, m: _Metrics) -> str:
        return f"""
        /* ---- Chat page ---- */
        QFrame#chatComposerContainer {{
            background: {c.input_bg};
            border: 1px solid {c.border};
            border-radius: {m.radius_sm};
        }}
        QScrollArea#chatScrollArea {{
            background: {c.panel_bg};
            border: none;
        }}
        QWidget#messageListContainer {{
            background: {c.panel_bg};
        }}
        QFrame#chatTurnDivider {{
            background: {c.border_light};
            margin-left: {m.spacing_4xl};
            margin-right: {m.spacing_4xl};
            margin-top: {m.spacing_md};
            margin-bottom: {m.spacing_md};
        }}
        QFrame#chatMessageBlock {{
            background: transparent;
            border: none;
        }}"""

    # -- Chat role labels --

    @staticmethod
    def _chat_role_styles(c: _Palette, m: _Metrics) -> str:
        return f"""
        QLabel#chatRoleUser {{
            color: {c.accent};
            font-size: {m.font_size_sm};
            font-weight: {m.font_weight_semibold};
            padding: 0px;
        }}
        QLabel#chatRoleAssistant {{
            color: {c.text_secondary};
            font-size: {m.font_size_sm};
            font-weight: {m.font_weight_semibold};
            padding: 0px;
        }}
        QLabel#chatMessageText {{
            color: {c.text_primary};
            font-size: {m.font_size_base};
            line-height: {m.line_height_normal};
        }}"""

    # -- Chat thinking indicator --

    @staticmethod
    def _chat_thinking_styles(c: _Palette, m: _Metrics) -> str:
        return f"""
        QWidget#chatThinkingIndicator {{
            background: transparent;
        }}
        QLabel#chatThinkingDot {{
            color: {c.accent};
            font-size: {m.spacing_2xl};
            font-weight: bold;
        }}"""

    # -- Tool trace card (legacy) --

    @staticmethod
    def _tool_trace_card_styles(c: _Palette, m: _Metrics) -> str:
        return f"""
        QFrame#toolTraceCard {{
            background: {c.border_light};
            border: 1px solid {c.border};
            border-radius: {m.radius_lg};
            margin-left: {m.spacing_4xl};
            margin-right: {m.spacing_4xl};
        }}
        QLabel#toolTraceTool {{
            color: {c.text_secondary};
            font-size: {m.font_size_sm};
            font-weight: {m.font_weight_semibold};
        }}
        QLabel#toolTraceStatus {{
            color: {c.text_secondary};
            font-size: {m.font_size_xs};
        }}"""

    # -- Tool call card --

    @staticmethod
    def _tool_call_styles(c: _Palette, m: _Metrics) -> str:
        return f"""
        /* ---- Tool call card ---- */
        QFrame#toolCallCard {{
            background: {c.border_light};
            border: 1px solid {c.border};
            border-radius: {m.radius_lg};
            margin-left: {m.spacing_4xl};
            margin-right: {m.spacing_4xl};
        }}
        QFrame#toolCallCard:hover {{
            border-color: {c.accent};
        }}
        QToolButton#toolCallToggle {{
            background: transparent;
            border: none;
            padding: {m.spacing_xxs};
        }}
        QToolButton#toolCallToggle:hover {{
            background: {c.hover_bg};
            border-radius: {m.radius_xs};
        }}
        QLabel#toolCallIcon {{
            color: {c.text_secondary};
            font-size: {m.font_size_base};
        }}
        QLabel#toolCallName {{
            color: {c.text_primary};
            font-size: {m.font_size_sm};
            font-weight: {m.font_weight_semibold};
        }}
        QLabel#toolCallStatus {{
            color: {c.text_secondary};
            font-size: {m.font_size_xs};
        }}
        QLabel#toolCallSummary {{
            color: {c.text_secondary};
            font-size: {m.font_size_xs};
            padding-left: 22px;
        }}
        QWidget#toolCallDetailPanel {{
            background: transparent;
        }}
        QLabel#toolCallSectionLabel {{
            color: {c.text_secondary};
            font-size: {m.font_size_xs};
            font-weight: {m.font_weight_semibold};
            text-transform: uppercase;
        }}
        QTextBrowser#toolCallContent {{
            background: {c.sidebar_bg};
            color: {c.text_primary};
            border: 1px solid {c.border};
            border-radius: {m.radius_sm};
            font-family: {m.mono_family};
            font-size: {m.font_size_sm};
            padding: {m.spacing_xs} {m.spacing_sm};
        }}"""

    # -- Chat input --

    @staticmethod
    def _chat_input_styles(c: _Palette, m: _Metrics) -> str:
        return f"""
        QTextEdit#chatInput {{
            background: transparent;
            color: {c.text_primary};
            border: none;
            border-radius: {m.radius_sm};
            padding: {m.spacing_sm} {m.spacing_md};
            font-size: {m.font_size_base};
        }}
        QTextEdit#chatInput:focus {{
            background: transparent;
        }}
        QTextEdit#chatInput:disabled {{
            color: {c.text_secondary};
        }}"""

    # -- Chat action buttons --

    @staticmethod
    def _chat_button_styles(c: _Palette, m: _Metrics) -> str:
        return f"""
        QPushButton#chatModelButton {{
            background: transparent;
            color: {c.text_secondary};
            border: none;
            border-radius: {m.radius_xl};
            padding: {m.spacing_xs} {m.spacing_lg};
            font-size: {m.font_size_sm};
            font-weight: {m.font_weight_medium};
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
            border-radius: {m.radius_round};
            font-size: {m.font_size_lg};
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
        QPushButton#chatStopRoundButton {{
            background: {c.status_error};
            color: {c.accent_text};
            border: none;
            border-radius: {m.radius_round};
            font-size: {m.font_size_md};
            font-weight: bold;
            padding: 0px;
        }}
        QPushButton#chatStopRoundButton:hover {{
            background: {c.status_error};
        }}
        QPushButton#chatClearButton {{
            background: transparent;
            color: {c.text_secondary};
            border: none;
            border-radius: 14px;
            font-size: 13pt;
            padding: 0px;
        }}
        QPushButton#chatClearButton:hover {{
            background: {c.hover_bg};
            color: {c.text_primary};
        }}"""

    # -- Chat model menu --

    @staticmethod
    def _chat_menu_styles(c: _Palette, m: _Metrics) -> str:
        return f"""
        QMenu#chatModelMenu {{
            background: {c.panel_bg};
            border: 1px solid {c.border};
            border-radius: {m.radius_lg};
            padding: {m.spacing_xs};
        }}
        QMenu#chatModelMenu::item {{
            padding: {m.spacing_sm} 20px;
            border-radius: {m.radius_sm};
            color: {c.text_primary};
        }}
        QMenu#chatModelMenu::item:selected {{
            background: {c.accent_subtle};
            color: {c.accent};
        }}
        QMenu#chatModelMenu::item:checked {{
            background: {c.accent_subtle};
            color: {c.accent};
            font-weight: {m.font_weight_semibold};
        }}
        QMenu#chatModelMenu::indicator {{
            width: {m.spacing_md};
            height: {m.spacing_md};
            border-radius: {m.radius_sm};
            background: {c.accent};
            margin-left: {m.spacing_xs};
        }}"""

    # -- Session sidebar --

    @staticmethod
    def _session_sidebar_styles(c: _Palette, m: _Metrics) -> str:
        return f"""
        /* ---- Session sidebar ---- */
        QFrame#sessionSidebar {{
            background: {c.sidebar_bg};
            border: none;
            border-right: 1px solid {c.border};
        }}
        QFrame#sessionSidebarHeader {{
            background: {c.sidebar_bg};
            border: none;
            border-bottom: 1px solid {c.border_light};
        }}
        QLabel#sessionSidebarTitle {{
            color: {c.text_secondary};
            font-size: {m.font_size_sm};
            font-weight: {m.font_weight_semibold};
            letter-spacing: {m.letter_spacing_normal};
        }}
        QPushButton#sessionNewButton {{
            background: transparent;
            color: {c.text_primary};
            border: 1px solid {c.border};
            border-radius: {m.radius_xl};
            font-size: {m.font_size_lg};
            font-weight: bold;
            padding: 0px;
        }}
        QPushButton#sessionNewButton:hover {{
            background: {c.accent_subtle};
            color: {c.accent};
            border: 1px solid {c.accent};
        }}
        QFrame#sessionItem {{
            background: transparent;
            border: none;
            border-radius: {m.radius_md};
        }}
        QFrame#sessionItem:hover {{
            background: {c.hover_bg};
        }}
        QFrame#sessionItem[active="true"] {{
            background: {c.accent_subtle};
        }}
        QLabel#sessionItemTitle {{
            color: {c.text_primary};
            font-size: {m.font_size_sm};
            font-weight: {m.font_weight_semibold};
        }}
        QLabel#sessionItemMeta {{
            color: {c.text_secondary};
            font-size: {m.font_size_xs};
        }}
        QPushButton#sessionDeleteButton {{
            background: transparent;
            color: {c.text_secondary};
            border: none;
            border-radius: 9px;
            font-size: {m.font_size_md};
            font-weight: bold;
            padding: 0px;
        }}
        QPushButton#sessionDeleteButton:hover {{
            background: {c.status_error}1a;
            color: {c.status_error};
        }}"""

    # -- Skill card --

    @staticmethod
    def _skill_card_styles(c: _Palette, m: _Metrics) -> str:
        return f"""
        /* ---- Skill card (settings) ---- */
        QFrame#skillCard {{
            background: {c.input_bg};
            border: 1px solid {c.border};
            border-radius: {m.radius_md};
        }}
        QFrame#skillCard:hover {{
            border: 1px solid {c.accent};
        }}"""

    # -- Chat skill/provider selectors --

    @staticmethod
    def _chat_skill_styles(c: _Palette, m: _Metrics) -> str:
        return f"""
        /* ---- Chat skill/provider selectors ---- */
        QPushButton#chatSkillButton {{
            background: transparent;
            color: {c.text_secondary};
            border: none;
            border-radius: {m.radius_xl};
            padding: {m.spacing_xs} {m.spacing_lg};
            font-size: {m.font_size_sm};
            font-weight: {m.font_weight_medium};
            text-align: left;
        }}
        QPushButton#chatSkillButton:hover {{
            background: {c.accent_subtle};
            color: {c.accent};
        }}"""

    # -- Chat markdown content --

    @staticmethod
    def _chat_markdown_styles(c: _Palette, m: _Metrics) -> str:
        return f"""
        /* ---- Chat markdown content ---- */
        QTextBrowser#chatMarkdownContent {{
            background: transparent;
            color: {c.text_primary};
            border: none;
            font-size: {m.font_size_base};
            padding: 4px;
        }}"""

    # -- Tool trace panel --

    @staticmethod
    def _tool_trace_panel_styles(c: _Palette, m: _Metrics) -> str:
        return f"""
        /* ---- Tool trace panel ---- */
        QWidget#toolTracePanel {{
            background: {c.panel_bg};
            border: none;
            border-left: 1px solid {c.border};
        }}
        QWidget#traceListContainer {{
            background: {c.panel_bg};
        }}
        QFrame#tracePanelHeader {{
            background: {c.header_bg};
            border: none;
            border-bottom: 1px solid {c.border_light};
        }}
        QLabel#tracePanelTitle {{
            color: {c.text_secondary};
            font-size: {m.font_size_sm};
            font-weight: {m.font_weight_semibold};
        }}
        QLabel#tracePanelCount {{
            color: {c.text_secondary};
            font-size: {m.font_size_xs};
        }}
        QFrame#traceEntry {{
            background: {c.input_bg};
            border: 1px solid {c.border};
            border-radius: {m.radius_md};
        }}
        QLabel#traceIcon {{
            color: {c.text_secondary};
            font-size: {m.font_size_sm};
        }}
        QLabel#traceToolName {{
            color: {c.text_primary};
            font-size: {m.font_size_sm};
            font-weight: {m.font_weight_semibold};
        }}
        QLabel#traceStatus {{
            color: {c.text_secondary};
            font-size: {m.font_size_xs};
        }}
        QLabel#traceArgs {{
            color: {c.text_secondary};
            font-size: {m.font_size_xs};
            font-family: {m.mono_family};
        }}
        QLabel#traceSummary {{
            color: {c.text_secondary};
            font-size: {m.font_size_xs};
        }}"""

    # -- Settings advanced toggle --

    @staticmethod
    def _advanced_toggle_styles(c: _Palette, m: _Metrics) -> str:
        return f"""
        /* ---- Settings advanced toggle ---- */
        QToolButton#advancedToggle {{
            background: transparent;
            color: {c.text_secondary};
            border: none;
            font-weight: bold;
            font-size: {m.font_size_sm};
            padding: {m.spacing_xxs} 0;
        }}
        QToolButton#advancedToggle:hover {{
            color: {c.text_primary};
        }}"""

    # -- Settings skill prompt edit --

    @staticmethod
    def _skill_prompt_styles(c: _Palette, m: _Metrics) -> str:
        return f"""
        /* ---- Settings skill prompt edit ---- */
        QTextEdit#skillPromptEdit {{
            background: {c.input_bg};
            color: {c.text_primary};
            border: 1px solid {c.border};
            border-radius: {m.radius_md};
            font-size: {m.font_size_sm};
        }}
        QTextEdit#skillPromptEdit:focus {{
            border: 2px solid {c.accent};
        }}"""

    # -- Scroll area containers inside panels --

    @staticmethod
    def _scroll_container_styles(c: _Palette, m: _Metrics) -> str:  # noqa: ARG004
        return f"""
        /* ---- Scroll area containers inside panels ---- */
        QWidget#sessionListContainer {{
            background: {c.sidebar_bg};
        }}
        QWidget#traceListContainer {{
            background: {c.panel_bg};
        }}
        QScrollArea#sessionScrollArea,
        QScrollArea#traceScrollArea {{
            background: transparent;
            border: none;
        }}"""

    # -- Additional menu styles --

    @staticmethod
    def _provider_menu_styles(c: _Palette, m: _Metrics) -> str:
        return f"""
        /* ---- Additional menu styles ---- */
        QMenu#chatProviderMenu,
        QMenu#chatSkillMenu {{
            background: {c.panel_bg};
            border: 1px solid {c.border};
            border-radius: {m.radius_lg};
            padding: {m.spacing_xs};
        }}
        QMenu#chatProviderMenu::item,
        QMenu#chatSkillMenu::item {{
            padding: {m.spacing_sm} 20px;
            border-radius: {m.radius_sm};
            color: {c.text_primary};
        }}
        QMenu#chatProviderMenu::item:selected,
        QMenu#chatSkillMenu::item:selected {{
            background: {c.accent_subtle};
            color: {c.accent};
        }}
        QMenu#chatProviderMenu::item:checked,
        QMenu#chatSkillMenu::item:checked {{
            background: {c.accent_subtle};
            color: {c.accent};
            font-weight: {m.font_weight_semibold};
        }}"""

    # ------------------------------------------------------------------ #
    # Factory helpers
    # ------------------------------------------------------------------ #

    @classmethod
    def light(cls) -> "Theme":
        return cls(ThemeMode.LIGHT)

    @classmethod
    def dark(cls) -> "Theme":
        return cls(ThemeMode.DARK)
