#ifndef PRO_WINDOW_H
#define PRO_WINDOW_H

#include <QMainWindow>
#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QPushButton>
#include <QLineEdit>
#include <QLabel>
#include <QGroupBox>
#include <QCheckBox>
#include <QStatusBar>
#include <QPixmap>
#include <QScrollArea>
#include <QComboBox>

#include "packet_collector.h"
#include "wifi_collector.h"
#include "config_reader.h"

typedef struct _capture_file capture_file;

class ProWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit ProWindow(QWidget *parent = nullptr);
    ~ProWindow();

    void setCaptureFile(capture_file *cf);
    void refreshOverview();

public slots:
    void onRefreshOverview();
    void onChooseLogoClicked();
    void onClearLogoClicked();
    void onGenerateSummary();
    void onGenerateDetailed();
    void onGenerateAnnotated();
    void onGenerateWifiSummary();
    void onGenerateWifiDetailed();
    void onGenerateWifiAnnotated();
    void onShowHelp();

private:
    void setupUI();
    void createOverviewGroup();
    void createCoverSettingsGroup();
    void createReportButtonsGroup(QVBoxLayout *parentLayout);
    void updateLogoPreview(const QString &path);
    const paper_size_t *selectedPaper();
    void generateNetworkReport(gboolean detailed);
    void generateAnnotatedReport();
    void generateWifiSummaryReport();
    void generateWifiDetailedReport();
    void generateWifiAnnotatedReport();
    reporter_config_t *buildConfigFromUI();
    void setReportButtonsEnabled(bool enabled);

    capture_file *m_cf;

    /* Overview widgets */
    QGroupBox  *m_overviewGroup;
    QLabel     *m_overviewLabel;

    /* Cover page settings */
    QGroupBox  *m_coverGroup;
    QLabel     *m_logoPreview;
    QString     m_logoPath;
    QPushButton *m_btnChooseLogo;
    QPushButton *m_btnClearLogo;
    QLineEdit  *m_editLine1;
    QLineEdit  *m_editLine2;
    QLineEdit  *m_editLine3;
    QCheckBox  *m_chkSaveDefaults;

    /* Paper size selector */
    QComboBox   *m_cbPaperSize;

    /* Report buttons */
    QPushButton *m_btnSummary;
    QPushButton *m_btnDetailed;
    QPushButton *m_btnAnnotated;
    QPushButton *m_btnWifiSummary;
    QPushButton *m_btnWifiDetailed;
    QPushButton *m_btnWifiAnnotated;
};

#endif /* PRO_WINDOW_H */
