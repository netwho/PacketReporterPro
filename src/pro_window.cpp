#include "pro_window.h"
#include "ui_bridge.h"
#include "packet_collector.h"
#include "wifi_collector.h"
#include "report_renderer.h"
#include "pdf_export.h"
#include "config_reader.h"
#include "reporter_plugin.h"

#include <QApplication>
#include <QFileDialog>
#include <QMessageBox>
#include <QStyle>
#include <QFont>
#include <QDateTime>
#include <QDesktopServices>
#include <QUrl>
#include <QFileInfo>
#include <QDebug>
#include <QDialog>
#include <QTextBrowser>
#include <QPalette>
#include <QFrame>
#include <epan/plugin_if.h>
#include <wsutil/wslog.h>
#include <cfile.h>
#include <cmath>

#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

/* ----------------------------------------------------------------
 * Constructor / Destructor
 * ---------------------------------------------------------------- */

ProWindow::ProWindow(QWidget *parent)
    : QMainWindow(parent)
    , m_cf(nullptr)
    , m_overviewGroup(nullptr)
    , m_overviewLabel(nullptr)
    , m_coverGroup(nullptr)
    , m_logoPreview(nullptr)
    , m_btnChooseLogo(nullptr)
    , m_btnClearLogo(nullptr)
    , m_editLine1(nullptr)
    , m_editLine2(nullptr)
    , m_editLine3(nullptr)
    , m_chkSaveDefaults(nullptr)
    , m_cbPaperSize(nullptr)
    , m_btnSummary(nullptr)
    , m_btnDetailed(nullptr)
    , m_btnAnnotated(nullptr)
    , m_btnWifiSummary(nullptr)
    , m_btnWifiDetailed(nullptr)
    , m_btnWifiAnnotated(nullptr)
{
    setupUI();
}

ProWindow::~ProWindow()
{
}

/* ----------------------------------------------------------------
 * Theme detection
 * ---------------------------------------------------------------- */

static bool isDarkTheme()
{
    QColor bg = QApplication::palette().color(QPalette::Window);
    double lum = 0.2126 * bg.redF() + 0.7152 * bg.greenF() + 0.0722 * bg.blueF();
    return lum < 0.45;
}

/* ----------------------------------------------------------------
 * UI Setup
 * ---------------------------------------------------------------- */

void ProWindow::setupUI()
{
    setWindowTitle("PacketReporter Pro " PLUGIN_VERSION_STR);
    setMinimumSize(640, 520);
    resize(700, 720);

    bool dark = isDarkTheme();

    QScrollArea *scroll = new QScrollArea(this);
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    setCentralWidget(scroll);

    QWidget *central = new QWidget();
    scroll->setWidget(central);

    QVBoxLayout *mainLayout = new QVBoxLayout(central);
    mainLayout->setSpacing(10);
    mainLayout->setContentsMargins(16, 16, 16, 16);

    /* Title row with help button */
    QHBoxLayout *titleRow = new QHBoxLayout();
    QLabel *title = new QLabel("PacketReporter Pro " PLUGIN_VERSION_STR, central);
    QFont titleFont("sans-serif", 18, QFont::Bold);
    title->setFont(titleFont);
    title->setStyleSheet(dark ? "color: #5AADE0;" : "color: #2C7BB6;");
    titleRow->addWidget(title);
    titleRow->addStretch();

    QPushButton *helpBtn = new QPushButton("?", central);
    helpBtn->setFixedSize(30, 30);
    helpBtn->setStyleSheet(QString(
        "QPushButton {"
        "  background-color: %1; color: white;"
        "  border: none; border-radius: 15px;"
        "  font-weight: bold; font-size: 16px;"
        "}"
        "QPushButton:hover { background-color: %2; }")
        .arg(dark ? "#3A8FCC" : "#2C7BB6",
             dark ? "#5AADE0" : "#1a5f94"));
    helpBtn->setToolTip("Help");
    titleRow->addWidget(helpBtn);
    connect(helpBtn, &QPushButton::clicked, this, &ProWindow::onShowHelp);

    mainLayout->addLayout(titleRow);

    createOverviewGroup();
    mainLayout->addWidget(m_overviewGroup);

    createCoverSettingsGroup();
    mainLayout->addWidget(m_coverGroup);

    createReportButtonsGroup(mainLayout);

    mainLayout->addStretch();

    statusBar()->showMessage("Ready — open a capture file and click a report button.");
}

void ProWindow::createOverviewGroup()
{
    bool dark = isDarkTheme();
    m_overviewGroup = new QGroupBox("Capture Overview", this);
    QVBoxLayout *vbox = new QVBoxLayout(m_overviewGroup);
    vbox->setSpacing(6);

    m_overviewLabel = new QLabel(m_overviewGroup);
    m_overviewLabel->setTextFormat(Qt::RichText);
    m_overviewLabel->setWordWrap(false);
    m_overviewLabel->setMinimumHeight(80);
    m_overviewLabel->setText(
        QString("<span style='color:%1;'>Open a capture file, then click Refresh</span>")
            .arg(dark ? "#aaa" : "#999"));
    vbox->addWidget(m_overviewLabel);

    QPushButton *refreshBtn = new QPushButton("Refresh", m_overviewGroup);
    refreshBtn->setFixedWidth(90);
    refreshBtn->setFixedHeight(28);
    vbox->addWidget(refreshBtn, 0, Qt::AlignLeft);

    connect(refreshBtn, &QPushButton::clicked,
            this, &ProWindow::onRefreshOverview);
}

void ProWindow::createCoverSettingsGroup()
{
    bool dark = isDarkTheme();
    m_coverGroup = new QGroupBox("Cover Page Settings", this);
    QVBoxLayout *outer = new QVBoxLayout(m_coverGroup);
    outer->setSpacing(6);

    /* Logo row */
    QHBoxLayout *logoRow = new QHBoxLayout();
    logoRow->setSpacing(8);

    m_logoPreview = new QLabel(m_coverGroup);
    m_logoPreview->setFixedSize(120, 60);
    m_logoPreview->setAlignment(Qt::AlignCenter);
    m_logoPreview->setStyleSheet(QString(
        "QLabel { background: %1; border: 1px solid %2; "
        "border-radius: 3px; color: %3; font-size: 10px; }")
        .arg(dark ? "#3a3a3a" : "#f0f0f0",
             dark ? "#555"    : "#ccc",
             dark ? "#aaa"    : "#999"));
    m_logoPreview->setText("No logo");
    logoRow->addWidget(m_logoPreview);

    m_btnChooseLogo = new QPushButton("Choose Logo...", m_coverGroup);
    m_btnClearLogo  = new QPushButton("Clear", m_coverGroup);
    m_btnClearLogo->setEnabled(false);
    logoRow->addWidget(m_btnChooseLogo);
    logoRow->addWidget(m_btnClearLogo);
    logoRow->addStretch();
    outer->addLayout(logoRow);

    connect(m_btnChooseLogo, &QPushButton::clicked,
            this, &ProWindow::onChooseLogoClicked);
    connect(m_btnClearLogo, &QPushButton::clicked,
            this, &ProWindow::onClearLogoClicked);

    /* Description lines */
    outer->addWidget(new QLabel("Description (3 lines on cover page):", m_coverGroup));

    m_editLine1 = new QLineEdit(m_coverGroup);
    m_editLine1->setPlaceholderText("Line 1 — e.g. Customer name");
    m_editLine1->setFixedHeight(26);
    outer->addWidget(m_editLine1);

    m_editLine2 = new QLineEdit(m_coverGroup);
    m_editLine2->setPlaceholderText("Line 2 — e.g. Network segment");
    m_editLine2->setFixedHeight(26);
    outer->addWidget(m_editLine2);

    m_editLine3 = new QLineEdit(m_coverGroup);
    m_editLine3->setPlaceholderText("Line 3 — e.g. Notes");
    m_editLine3->setFixedHeight(26);
    outer->addWidget(m_editLine3);

    m_chkSaveDefaults = new QCheckBox("Save as defaults for future reports", m_coverGroup);
    outer->addWidget(m_chkSaveDefaults);

    reporter_config_t *cfg = config_reader_load();
    if (cfg) {
        if (cfg->desc_line1) m_editLine1->setText(QString::fromUtf8(cfg->desc_line1));
        if (cfg->desc_line2) m_editLine2->setText(QString::fromUtf8(cfg->desc_line2));
        if (cfg->desc_line3) m_editLine3->setText(QString::fromUtf8(cfg->desc_line3));

        if (cfg->logo_loaded) {
            char *dir = config_reader_get_dir();
            m_logoPath = QString::fromUtf8(dir) + "/Logo.png";
            g_free(dir);
            updateLogoPreview(m_logoPath);
        }
        config_reader_free(cfg);
    }
}

void ProWindow::createReportButtonsGroup(QVBoxLayout *parentLayout)
{
    bool dark = isDarkTheme();
    QGroupBox *reportGroup = new QGroupBox("Generate Report", this);
    QVBoxLayout *outer = new QVBoxLayout(reportGroup);
    outer->setSpacing(6);

    /* Paper size selector */
    QHBoxLayout *paperRow = new QHBoxLayout();
    paperRow->addWidget(new QLabel("Paper Size:", reportGroup));
    m_cbPaperSize = new QComboBox(reportGroup);
    m_cbPaperSize->addItem("A4", QVariant(PAPER_A4));
    m_cbPaperSize->addItem("Legal", QVariant(PAPER_LEGAL));
    m_cbPaperSize->setCurrentIndex(0);
    m_cbPaperSize->setFixedWidth(100);
    paperRow->addWidget(m_cbPaperSize);
    paperRow->addStretch();
    outer->addLayout(paperRow);

    outer->addSpacing(4);

    QString disabledBg = dark ? "#555" : "#aaa";
    const char *btnCss =
        "QPushButton {"
        "  background-color: %1; color: white;"
        "  border: none; border-radius: 4px;"
        "  padding: 6px 12px; font-weight: bold; font-size: 11px;"
        "}"
        "QPushButton:hover { background-color: %2; }"
        "QPushButton:disabled { background-color: %3; }";

    QString netColor  = dark ? "#5AADE0" : "#2C7BB6";
    QString wifiColor = dark ? "#40C8E8" : "#00A6CA";

    QString netStyle  = QString(btnCss).arg(netColor,  dark ? "#2C7BB6" : "#1a5f94", disabledBg);
    QString wifiStyle = QString(btnCss).arg(wifiColor, dark ? "#00A6CA" : "#0088a8", disabledBg);

    auto makeBtn = [&](const QString &text, const QString &style) {
        QPushButton *btn = new QPushButton(text, reportGroup);
        btn->setStyleSheet(style);
        btn->setFixedHeight(32);
        return btn;
    };

    /* 1. Network Analysis */
    QLabel *lbl1 = new QLabel("Network Analysis", reportGroup);
    lbl1->setStyleSheet(QString("font-weight:bold; color:%1;").arg(netColor));
    outer->addWidget(lbl1);

    QHBoxLayout *netRow = new QHBoxLayout();
    netRow->setSpacing(6);
    m_btnSummary   = makeBtn("Summary (1 page)", netStyle);
    m_btnDetailed  = makeBtn("Detailed Report",  netStyle);
    m_btnAnnotated = makeBtn("Annotated Report", netStyle);
    netRow->addWidget(m_btnSummary);
    netRow->addWidget(m_btnDetailed);
    netRow->addWidget(m_btnAnnotated);
    outer->addLayout(netRow);
    connect(m_btnSummary, &QPushButton::clicked,
            this, &ProWindow::onGenerateSummary);
    connect(m_btnDetailed, &QPushButton::clicked,
            this, &ProWindow::onGenerateDetailed);
    connect(m_btnAnnotated, &QPushButton::clicked,
            this, &ProWindow::onGenerateAnnotated);

    /* 2. WiFi / 802.11 Analysis */
    outer->addSpacing(4);
    QLabel *lbl2 = new QLabel("WiFi / 802.11 Analysis", reportGroup);
    lbl2->setStyleSheet(QString("font-weight:bold; color:%1;").arg(wifiColor));
    outer->addWidget(lbl2);

    QHBoxLayout *wifiRow = new QHBoxLayout();
    wifiRow->setSpacing(6);
    m_btnWifiSummary   = makeBtn("Summary (1 page)", wifiStyle);
    m_btnWifiDetailed  = makeBtn("Detailed Report",  wifiStyle);
    m_btnWifiAnnotated = makeBtn("Annotated Report", wifiStyle);
    wifiRow->addWidget(m_btnWifiSummary);
    wifiRow->addWidget(m_btnWifiDetailed);
    wifiRow->addWidget(m_btnWifiAnnotated);
    outer->addLayout(wifiRow);
    connect(m_btnWifiSummary, &QPushButton::clicked,
            this, &ProWindow::onGenerateWifiSummary);
    connect(m_btnWifiDetailed, &QPushButton::clicked,
            this, &ProWindow::onGenerateWifiDetailed);
    connect(m_btnWifiAnnotated, &QPushButton::clicked,
            this, &ProWindow::onGenerateWifiAnnotated);

    parentLayout->addWidget(reportGroup);
}

/* ----------------------------------------------------------------
 * Capture file & overview
 * ---------------------------------------------------------------- */

void ProWindow::setCaptureFile(capture_file *cf)
{
    m_cf = cf;
    refreshOverview();
}

static capture_file *find_cfile_via_dlsym()
{
#ifdef _WIN32
    void *sym = (void *)GetProcAddress(GetModuleHandle(NULL), "cfile");
#else
    void *sym = dlsym(RTLD_DEFAULT, "cfile");
#endif
    if (sym)
        return (capture_file *)sym;
    return NULL;
}

void ProWindow::onRefreshOverview()
{
    /* Always re-resolve cf via dlsym — most reliable method */
    capture_file *cf = find_cfile_via_dlsym();
    if (cf)
        m_cf = cf;

    refreshOverview();
}

static QString formatNumber(double v)
{
    if (v >= 1e9)      return QString::number(v / 1e9, 'f', 1) + " G";
    else if (v >= 1e6) return QString::number(v / 1e6, 'f', 1) + " M";
    else if (v >= 1e3) return QString::number(v / 1e3, 'f', 1) + " k";
    else               return QString::number(v, 'f', 1);
}

static QString formatBytes(guint64 b)
{
    if (b >= 1073741824ULL) return QString::number((double)b / 1073741824.0, 'f', 1) + " GB";
    if (b >= 1048576ULL)    return QString::number((double)b / 1048576.0, 'f', 1) + " MB";
    if (b >= 1024ULL)       return QString::number((double)b / 1024.0, 'f', 1) + " KB";
    return QString::number(b) + " B";
}

static QString formatDuration(double secs)
{
    if (secs <= 0.0) return "0 s";
    int h = (int)(secs / 3600);
    int m = (int)(fmod(secs, 3600) / 60);
    double s = fmod(secs, 60);
    if (h > 0)
        return QString("%1:%2:%3")
            .arg(h).arg(m, 2, 10, QChar('0'))
            .arg(s, 5, 'f', 2, QChar('0'));
    if (m > 0)
        return QString("%1:%2").arg(m).arg(s, 5, 'f', 2, QChar('0'));
    return QString::number(secs, 'f', 3) + " s";
}

static QString buildOverviewHtml(const file_summary_t &s, const QString &fname)
{
    bool dark = isDarkTheme();
    QString muted = dark ? "#aaa" : "#888";

    auto cell = [](const QString &label, const QString &value) {
        return QString("<td style='padding:2px 10px 2px 0; font-weight:bold;'>%1</td>"
                       "<td style='padding:2px 16px 2px 0;'>%2</td>")
            .arg(label, value);
    };

    QString encap = s.encapsulation
        ? QString::fromUtf8(s.encapsulation) : "Unknown";

    QString html = "<table cellspacing='0' cellpadding='0'><tr>";
    html += cell("Packets:", QString::number(s.packets));
    html += cell("Link Type:", encap);
    html += "</tr><tr>";
    html += cell("Duration:", formatDuration(s.duration_s));
    html += cell("Source:", fname.toHtmlEscaped());
    html += "</tr></table>";

    html += QString("<table cellspacing='0' cellpadding='0' style='margin-top:4px; "
                    "font-size:10px; color:%1;'><tr>").arg(muted);
    html += cell("Bytes:", formatBytes(s.bytes));
    html += cell("Avg pps:", formatNumber(s.avg_pps));
    html += cell("Avg Pkt:", QString::number((int)s.avg_packet_size) + " B");
    html += cell("Throughput:", formatNumber(s.avg_bytes_per_sec) + "/s");
    html += "</tr></table>";

    return html;
}

void ProWindow::refreshOverview()
{
    /* Step 1: Get the filename */
    QString filename;
    ws_info_t *info = NULL;
    plugin_if_get_ws_info(&info);
    if (info && info->ws_info_supported && info->cf_filename) {
        filename = QString::fromUtf8(info->cf_filename);
    }
    if (filename.isEmpty() && m_cf && m_cf->filename) {
        filename = QString::fromUtf8(m_cf->filename);
    }
    if (filename.isEmpty()) {
        capture_file *cf = find_cfile_via_dlsym();
        if (cf && cf->filename) {
            filename = QString::fromUtf8(cf->filename);
            m_cf = cf;
        }
    }

    if (filename.isEmpty()) {
        m_overviewLabel->setText(
            "<i>No capture file detected. Open a file and click Refresh.</i>");
        statusBar()->showMessage(
            "No capture file detected. Open a file and click Refresh.");
        return;
    }

    /* Step 2: Read the file directly with wtap */
    statusBar()->showMessage(
        QString("Reading %1 ...").arg(QFileInfo(filename).fileName()));
    m_overviewLabel->setText(
        QString("<i>Reading %1 ...</i>").arg(
            QFileInfo(filename).fileName().toHtmlEscaped()));
    QApplication::processEvents();

    file_summary_t s = packet_collector_file_summary(
        filename.toUtf8().constData());

    if (!s.valid || s.packets == 0) {
        m_overviewLabel->setText(
            QString("<i>File has 0 packets: %1</i>")
                .arg(filename.toHtmlEscaped()));
        statusBar()->showMessage(
            QString("File: %1 — 0 packets").arg(filename));
        packet_collector_free_file_summary(&s);
        return;
    }

    m_overviewLabel->setText(
        buildOverviewHtml(s, QFileInfo(filename).fileName()));

    statusBar()->showMessage(
        QString("Capture: %1 — %2 packets, %3 — ready to generate reports.")
            .arg(QFileInfo(filename).fileName())
            .arg(s.packets)
            .arg(formatDuration(s.duration_s)));

    packet_collector_free_file_summary(&s);
}

/* ----------------------------------------------------------------
 * Logo handling
 * ---------------------------------------------------------------- */

void ProWindow::onChooseLogoClicked()
{
    QString path = QFileDialog::getOpenFileName(
        this, "Select Logo Image",
        QString(),
        "Images (*.png *.jpg *.jpeg *.bmp);;All Files (*)");
    if (path.isEmpty()) return;

    m_logoPath = path;
    updateLogoPreview(path);
    m_btnClearLogo->setEnabled(true);
}

void ProWindow::onClearLogoClicked()
{
    m_logoPath.clear();
    m_logoPreview->setPixmap(QPixmap());
    m_logoPreview->setText("No logo");
    m_btnClearLogo->setEnabled(false);
}

void ProWindow::updateLogoPreview(const QString &path)
{
    QPixmap pix(path);
    if (pix.isNull()) {
        m_logoPreview->setText("Invalid image");
        return;
    }
    m_logoPreview->setPixmap(
        pix.scaled(m_logoPreview->size(),
                   Qt::KeepAspectRatio,
                   Qt::SmoothTransformation));
    m_logoPreview->setText(QString());
    m_btnClearLogo->setEnabled(true);
}

/* ----------------------------------------------------------------
 * Config from UI
 * ---------------------------------------------------------------- */

reporter_config_t *ProWindow::buildConfigFromUI()
{
    reporter_config_t *cfg = g_new0(reporter_config_t, 1);

    /* Logo */
    if (!m_logoPath.isEmpty()) {
        QByteArray pathBytes = m_logoPath.toUtf8();
        cfg->logo_surface = cairo_image_surface_create_from_png(
                                pathBytes.constData());
        if (cfg->logo_surface &&
            cairo_surface_status(cfg->logo_surface) == CAIRO_STATUS_SUCCESS) {
            cfg->logo_loaded = TRUE;
            cfg->logo_width  = cairo_image_surface_get_width(cfg->logo_surface);
            cfg->logo_height = cairo_image_surface_get_height(cfg->logo_surface);
        } else {
            if (cfg->logo_surface) {
                cairo_surface_destroy(cfg->logo_surface);
                cfg->logo_surface = NULL;
            }
        }
    }

    /* Description */
    cfg->desc_line1 = g_strdup(m_editLine1->text().toUtf8().constData());
    cfg->desc_line2 = g_strdup(m_editLine2->text().toUtf8().constData());
    cfg->desc_line3 = g_strdup(m_editLine3->text().toUtf8().constData());

    /* Save defaults if checked */
    if (m_chkSaveDefaults->isChecked()) {
        config_reader_save(cfg, m_logoPath.isEmpty() ? NULL
                           : m_logoPath.toUtf8().constData());
    }

    return cfg;
}

/* ----------------------------------------------------------------
 * Button enable / disable
 * ---------------------------------------------------------------- */

const paper_size_t *ProWindow::selectedPaper()
{
    return (m_cbPaperSize->currentData().toInt() == PAPER_LEGAL)
               ? &PAPER_LEGAL_SIZE
               : &PAPER_A4_SIZE;
}

void ProWindow::setReportButtonsEnabled(bool enabled)
{
    m_btnSummary->setEnabled(enabled);
    m_btnDetailed->setEnabled(enabled);
    m_btnAnnotated->setEnabled(enabled);
    m_btnWifiSummary->setEnabled(enabled);
    m_btnWifiDetailed->setEnabled(enabled);
    m_btnWifiAnnotated->setEnabled(enabled);
}

/* ----------------------------------------------------------------
 * Report generation — Network
 * ---------------------------------------------------------------- */

void ProWindow::onGenerateSummary()
{
    generateNetworkReport(FALSE);
}

void ProWindow::onGenerateDetailed()
{
    generateNetworkReport(TRUE);
}

void ProWindow::generateNetworkReport(gboolean detailed)
{
    if (!m_cf || m_cf->count == 0) {
        QMessageBox::warning(this, "PacketReporter Pro",
            "No capture file loaded or capture is empty.\n"
            "Please open a PCAP file in Wireshark first.");
        return;
    }

    setReportButtonsEnabled(false);
    statusBar()->showMessage(detailed
        ? "Generating detailed network report..."
        : "Generating summary network report...");
    QApplication::processEvents();

    collection_result_t *result = packet_collector_run(m_cf, detailed);
    reporter_config_t   *cfg    = buildConfigFromUI();

    char *pdf_path = NULL;
    if (detailed)
        pdf_path = pdf_export_detailed(result, cfg, selectedPaper(), NULL);
    else
        pdf_path = pdf_export_summary(result, cfg, NULL);

    config_reader_free(cfg);
    packet_collector_free_result(result);
    setReportButtonsEnabled(true);

    if (pdf_path) {
        statusBar()->showMessage(
            QString("Report saved: %1").arg(QString::fromUtf8(pdf_path)));
        pdf_export_open_file(pdf_path);
        g_free(pdf_path);
    } else {
        statusBar()->showMessage("Report generation failed.");
        QMessageBox::warning(this, "PacketReporter Pro",
            "Failed to generate the report.\n"
            "Check the Wireshark log for details.");
    }
}

/* ----------------------------------------------------------------
 * Report generation — Annotated
 * ---------------------------------------------------------------- */

void ProWindow::onGenerateAnnotated()
{
    generateAnnotatedReport();
}

void ProWindow::generateAnnotatedReport()
{
    if (!m_cf || m_cf->count == 0) {
        QMessageBox::warning(this, "PacketReporter Pro",
            "No capture file loaded or capture is empty.\n"
            "Please open a PCAP file in Wireshark first.");
        return;
    }

    setReportButtonsEnabled(false);
    statusBar()->showMessage("Generating annotated report...");
    QApplication::processEvents();

    collection_result_t *result = packet_collector_run(m_cf, TRUE);
    reporter_config_t   *cfg    = buildConfigFromUI();

    char *pdf_path = pdf_export_annotated(result, cfg, selectedPaper(), NULL);

    config_reader_free(cfg);
    packet_collector_free_result(result);
    setReportButtonsEnabled(true);

    if (pdf_path) {
        statusBar()->showMessage(
            QString("Report saved: %1").arg(QString::fromUtf8(pdf_path)));
        pdf_export_open_file(pdf_path);
        g_free(pdf_path);
    } else {
        statusBar()->showMessage("Report generation failed.");
        QMessageBox::warning(this, "PacketReporter Pro",
            "Failed to generate the annotated report.\n"
            "Check the Wireshark log for details.");
    }
}

/* ----------------------------------------------------------------
 * Report generation — WiFi / 802.11
 * ---------------------------------------------------------------- */

void ProWindow::onGenerateWifiSummary()
{
    generateWifiSummaryReport();
}

void ProWindow::onGenerateWifiDetailed()
{
    generateWifiDetailedReport();
}

void ProWindow::generateWifiSummaryReport()
{
    if (!m_cf || m_cf->count == 0) {
        QMessageBox::warning(this, "PacketReporter Pro",
            "No capture file loaded or capture is empty.\n"
            "Please open a PCAP file in Wireshark first.");
        return;
    }

    setReportButtonsEnabled(false);
    statusBar()->showMessage("Generating WiFi summary...");
    QApplication::processEvents();

    wifi_collection_result_t *result = wifi_collector_run(m_cf);
    reporter_config_t        *cfg    = buildConfigFromUI();

    char *pdf_path = pdf_export_wifi_summary(result, cfg, NULL);

    config_reader_free(cfg);
    wifi_collector_free_result(result);
    setReportButtonsEnabled(true);

    if (pdf_path) {
        statusBar()->showMessage(
            QString("Report saved: %1").arg(QString::fromUtf8(pdf_path)));
        pdf_export_open_file(pdf_path);
        g_free(pdf_path);
    } else {
        statusBar()->showMessage("WiFi summary generation failed.");
        QMessageBox::warning(this, "PacketReporter Pro",
            "Failed to generate the WiFi summary.\n"
            "This requires a capture with 802.11 (monitor mode) frames.\n"
            "Check the Wireshark log for details.");
    }
}

void ProWindow::generateWifiDetailedReport()
{
    if (!m_cf || m_cf->count == 0) {
        QMessageBox::warning(this, "PacketReporter Pro",
            "No capture file loaded or capture is empty.\n"
            "Please open a PCAP file in Wireshark first.");
        return;
    }

    setReportButtonsEnabled(false);
    statusBar()->showMessage("Generating WiFi detailed report...");
    QApplication::processEvents();

    wifi_collection_result_t *result = wifi_collector_run(m_cf);
    reporter_config_t        *cfg    = buildConfigFromUI();

    char *pdf_path = pdf_export_wifi(result, cfg, selectedPaper(), NULL);

    config_reader_free(cfg);
    wifi_collector_free_result(result);
    setReportButtonsEnabled(true);

    if (pdf_path) {
        statusBar()->showMessage(
            QString("Report saved: %1").arg(QString::fromUtf8(pdf_path)));
        pdf_export_open_file(pdf_path);
        g_free(pdf_path);
    } else {
        statusBar()->showMessage("WiFi report generation failed.");
        QMessageBox::warning(this, "PacketReporter Pro",
            "Failed to generate the WiFi report.\n"
            "This requires a capture with 802.11 (monitor mode) frames.\n"
            "Check the Wireshark log for details.");
    }
}

/* ----------------------------------------------------------------
 * Report generation — WiFi Annotated
 * ---------------------------------------------------------------- */

void ProWindow::onGenerateWifiAnnotated()
{
    generateWifiAnnotatedReport();
}

void ProWindow::generateWifiAnnotatedReport()
{
    if (!m_cf || m_cf->count == 0) {
        QMessageBox::warning(this, "PacketReporter Pro",
            "No capture file loaded or capture is empty.\n"
            "Please open a PCAP file in Wireshark first.");
        return;
    }

    setReportButtonsEnabled(false);
    statusBar()->showMessage("Generating WiFi annotated report...");
    QApplication::processEvents();

    wifi_collection_result_t *result = wifi_collector_run(m_cf);
    reporter_config_t        *cfg    = buildConfigFromUI();

    char *pdf_path = pdf_export_wifi_annotated(result, cfg, selectedPaper(), NULL);

    config_reader_free(cfg);
    wifi_collector_free_result(result);
    setReportButtonsEnabled(true);

    if (pdf_path) {
        statusBar()->showMessage(
            QString("Report saved: %1").arg(QString::fromUtf8(pdf_path)));
        pdf_export_open_file(pdf_path);
        g_free(pdf_path);
    } else {
        statusBar()->showMessage("WiFi annotated report generation failed.");
        QMessageBox::warning(this, "PacketReporter Pro",
            "Failed to generate the WiFi annotated report.\n"
            "This requires a capture with 802.11 (monitor mode) frames.\n"
            "Check the Wireshark log for details.");
    }
}

/* ----------------------------------------------------------------
 * Help dialog
 * ---------------------------------------------------------------- */

void ProWindow::onShowHelp()
{
    bool dark = isDarkTheme();

    /* Theme-dependent palette */
    QString bgCol    = dark ? "#2b2b2b" : "white";
    QString textCol  = dark ? "#ddd"    : "#333";
    QString mutedCol = dark ? "#aaa"    : "#888";
    QString hrCol    = dark ? "#555"    : "#e0e0e0";
    QString tblBdr   = dark ? "#555"    : "#ddd";
    QString altRow   = dark ? "#333"    : "#f5f5f5";
    QString codeCol  = dark ? "#c8d0d8" : "#333";
    QString codeBg   = dark ? "#383838" : "#f0f0f0";
    QString footBg   = dark ? "#242424" : "#f8f8f8";
    QString titleCol = dark ? "#5AADE0" : "#2C7BB6";
    QString netCol   = dark ? "#5AADE0" : "#2C7BB6";
    QString wifiCol  = dark ? "#40C8E8" : "#00A6CA";
    QString warnCol  = dark ? "#e87070" : "#c44";
    QString linkCol  = dark ? "#5AADE0" : "#2C7BB6";

    QDialog *dlg = new QDialog(this);
    dlg->setWindowTitle("PacketReporter Pro \xe2\x80\x94 Help");
    dlg->setFixedSize(580, 640);
    dlg->setAttribute(Qt::WA_DeleteOnClose);

    QVBoxLayout *layout = new QVBoxLayout(dlg);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);

    QTextBrowser *browser = new QTextBrowser(dlg);
    browser->setOpenExternalLinks(true);
    browser->setStyleSheet(QString(
        "QTextBrowser {"
        "  background: %1; color: %2; border: none;"
        "  padding: 20px; font-size: 12px;"
        "}"
        "code { background: %3; color: %4; padding: 1px 4px; border-radius: 3px; }")
        .arg(bgCol, textCol, codeBg, codeCol));

    browser->setHtml(QString(
        "<h2 style='color:%1; margin-bottom:4px;'>PacketReporter Pro " PLUGIN_VERSION_STR "</h2>"
        "<p style='color:%2; margin-top:0;'>Professional PDF reports from Wireshark captures</p>"
        "<hr style='border:1px solid %3;'>"

        "<h3 style='color:%4;'>Getting Started</h3>"
        "<ol>"
        "<li><b>Open a capture file</b> in Wireshark (File \xe2\x86\x92 Open), "
            "then launch PacketReporter Pro from <b>Tools \xe2\x86\x92 PacketReporter Pro</b>.</li>"
        "<li>Click <b>Refresh</b> in the Capture Overview to load packet statistics.</li>"
        "<li>Optionally customize the <b>cover page</b>: choose a logo (PNG recommended, "
            "e.g. 900" "\xc3\x97" "300 px), enter up to 3 description lines (customer, segment, notes), "
            "and check \xe2\x80\x9cSave as defaults\xe2\x80\x9d to remember them.</li>"
        "<li>Select the <b>paper size</b> (A4 or US Legal) from the dropdown \xe2\x80\x94 "
            "this affects detailed and WiFi reports. A4 is the default.</li>"
        "<li>Click a <b>report button</b> to generate and open the PDF.</li>"
        "</ol>"

        "<h3 style='color:%4;'>Report Types</h3>"
        "<table cellspacing='0' cellpadding='4' style='border-collapse:collapse; width:100%%;'>"

        "<tr style='background:%5;'>"
        "  <td style='border:1px solid %6; padding:6px;'><b style='color:%7;'>Network Summary</b></td>"
        "  <td style='border:1px solid %6; padding:6px;'>One-page network statistics overview \xe2\x80\x94 "
            "packet/byte counts, protocols, and top IP addresses.</td>"
        "</tr>"
        "<tr>"
        "  <td style='border:1px solid %6; padding:6px;'><b style='color:%7;'>Network Detailed</b></td>"
        "  <td style='border:1px solid %6; padding:6px;'>Comprehensive multi-page report (12+ pages) with "
            "cover page, table of contents, and 11 analysis sections: PCAP summary, IP statistics, "
            "protocol distribution, communication matrix, DNS, TLS/SSL, HTTP, IP detail, "
            "application layer, WiFi (if present), and TCP analysis.</td>"
        "</tr>"
        "<tr style='background:%5;'>"
        "  <td style='border:1px solid %6; padding:6px;'><b style='color:%7;'>Annotated Report</b></td>"
        "  <td style='border:1px solid %6; padding:6px;'>Same content as the Detailed Report, but every "
            "section includes an annotation sidebar (right 1/3 of the page) explaining what the data "
            "means, where it comes from, and how to interpret it \xe2\x80\x94 ideal for sharing with "
            "non-experts or as a learning reference. Ends with a summary page.</td>"
        "</tr>"
        "<tr>"
        "  <td style='border:1px solid %6; padding:6px;'><b style='color:%8;'>WiFi Summary</b></td>"
        "  <td style='border:1px solid %6; padding:6px;'>One-page WiFi overview with key metrics "
            "(BSSIDs, clients, channels, RSSI, retry rate), channel pie chart, and top MAC talkers."
            "<br><i style='color:%9;'>Requires a WiFi monitor-mode capture (see below).</i></td>"
        "</tr>"
        "<tr style='background:%5;'>"
        "  <td style='border:1px solid %6; padding:6px;'><b style='color:%8;'>WiFi Detailed</b></td>"
        "  <td style='border:1px solid %6; padding:6px;'>Full multi-page 802.11 analysis (10 sections): "
            "PCAP summary &amp; SSIDs, top MACs, RSSI distribution, SNR distribution, channel usage, "
            "MCS rates, frame types, deauth/disassoc analysis, retry analysis, and airtime talkers."
            "<br><i style='color:%9;'>Requires a WiFi monitor-mode capture (see below).</i></td>"
        "</tr>"
        "<tr>"
        "  <td style='border:1px solid %6; padding:6px;'><b style='color:%8;'>WiFi Annotated</b></td>"
        "  <td style='border:1px solid %6; padding:6px;'>Same content as the WiFi Detailed Report, but every "
            "section includes an annotation sidebar explaining what the data means, where it comes from, "
            "and how to interpret it \xe2\x80\x94 ideal for WiFi troubleshooting by non-experts. "
            "Ends with a summary page."
            "<br><i style='color:%9;'>Requires a WiFi monitor-mode capture (see below).</i></td>"
        "</tr>"
        "</table>"

        "<h3 style='color:%4;'>WiFi Monitor Mode</h3>"
        "<p>The WiFi reports require a packet capture made in <b>monitor mode</b> (also called "
        "\xe2\x80\x9crfmon\xe2\x80\x9d mode). In monitor mode, the WiFi adapter captures <i>all</i> "
        "802.11 frames over the air \xe2\x80\x94 including management frames (beacons, probes, "
        "authentication), control frames, and data frames from all nearby networks \xe2\x80\x94 rather "
        "than only traffic on the connected network.</p>"
        "<p>This is required because WiFi reports analyze radiotap headers (RSSI, noise, data rate, "
        "MCS index), 802.11 MAC-layer fields (BSSID, frame types, retries), and channel information "
        "that are only present in monitor-mode captures.</p>"
        "<p><b>How to capture in monitor mode:</b></p>"
        "<ul>"
        "<li><b>macOS:</b> In Wireshark, select your WiFi interface, then go to "
            "<i>Capture \xe2\x86\x92 Options</i> and check \xe2\x80\x9cMonitor mode\xe2\x80\x9d "
            "(or use <code>airport</code> / <code>tcpdump</code> from Terminal).</li>"
        "<li><b>Linux:</b> Use <code>airmon-ng start wlan0</code> to create a monitor interface, "
            "then capture on the monitor interface (e.g. <code>wlan0mon</code>).</li>"
        "<li><b>Windows:</b> Requires a compatible adapter + Npcap in WiFi mode, or "
            "use an external capture tool (e.g. on a Linux/macOS device) and load the file.</li>"
        "</ul>"
        "<p style='color:%2;'>A regular WiFi capture (normal/managed mode) will <i>not</i> contain "
        "the radiotap and 802.11 headers needed for WiFi analysis.</p>"

        "<h3 style='color:%4;'>Output</h3>"
        "<p>Reports are saved as PDF files in <code>~/Documents/PacketReporter Reports/</code> "
        "and opened automatically in your default PDF viewer. Filenames include a timestamp "
        "so previous reports are never overwritten.</p>"

        "<h3 style='color:%4;'>Cover Page Customization</h3>"
        "<p>The detailed reports include a professional cover page. You can set:</p>"
        "<ul>"
        "<li><b>Logo</b> \xe2\x80\x94 a PNG or JPEG image (recommended: 900" "\xc3\x97" "300 px). "
            "Displayed at the top of the cover page.</li>"
        "<li><b>Description lines</b> \xe2\x80\x94 up to 3 lines (e.g. customer name, "
            "network segment, notes).</li>"
        "<li><b>Save as defaults</b> \xe2\x80\x94 stores logo and text to "
            "<code>~/.packet_reporter/</code> so they persist across sessions.</li>"
        "</ul>")
        .arg(titleCol)   /* %1 title */
        .arg(mutedCol)   /* %2 muted */
        .arg(hrCol)      /* %3 hr border */
        .arg(textCol)    /* %4 headings */
        .arg(altRow)     /* %5 alt row bg */
        .arg(tblBdr)     /* %6 table border */
        .arg(netCol)     /* %7 network color */
        .arg(wifiCol)    /* %8 wifi color */
        .arg(warnCol)    /* %9 warning color */
    );

    layout->addWidget(browser);

    /* Footer */
    QLabel *footer = new QLabel(dlg);
    footer->setTextFormat(Qt::RichText);
    footer->setOpenExternalLinks(true);
    footer->setAlignment(Qt::AlignCenter);
    footer->setStyleSheet(QString(
        "QLabel {"
        "  background: %1; border-top: 1px solid %2;"
        "  padding: 10px; color: %3; font-size: 11px;"
        "}").arg(footBg, hrCol, mutedCol));
    footer->setText(QString(
        "Built with \xe2\x9d\xa4\xef\xb8\x8f for the network analysis community "
        "\xe2\x80\x94 "
        "<a href='https://github.com/netwho/PacketCirclePro' "
        "style='color:%1;'>github.com/netwho/PacketCirclePro</a>")
        .arg(linkCol));
    layout->addWidget(footer);

    dlg->show();
}
