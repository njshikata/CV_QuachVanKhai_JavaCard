package main;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.geom.RoundRectangle2D;

public class MainBackendGui extends JFrame {

    private final CardService cardService;
    private final CardPanel cardPanel;
    private final JButton btnTapCard;

    private boolean isFlashing = false;
    private boolean isError = false;
    private String statusText = "SẴN SÀNG CHỜ QUÉT (BRIDGE :8088)";

    public MainBackendGui() {
        setTitle("Virtual Smart Card Reader (:8088 -> :8080)");
        setSize(460, 360);
        setResizable(false);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        cardService = new CardService();
        try {
            CardBridgeServer.start(cardService);
        } catch (Exception ex) {
            isError = true;
            statusText = "LỖI MỞ CỔNG 8088: " + ex.getMessage();
        }

        cardService.setStatusListener(msg -> SwingUtilities.invokeLater(() -> flashCard(msg, false)));

        JPanel root = new JPanel(new BorderLayout(15, 15));
        root.setBackground(new Color(24, 26, 32));
        root.setBorder(new EmptyBorder(20, 25, 20, 25));

        cardPanel = new CardPanel();
        root.add(cardPanel, BorderLayout.CENTER);

        btnTapCard = new JButton("📡 QUÉT THẺ");
        btnTapCard.setFont(new Font("Arial", Font.BOLD, 16));
        btnTapCard.setPreferredSize(new Dimension(0, 48));
        btnTapCard.setBackground(new Color(0, 150, 90));
        btnTapCard.setForeground(Color.WHITE);
        btnTapCard.setFocusPainted(false);
        btnTapCard.setBorderPainted(false);
        btnTapCard.setOpaque(true);
        btnTapCard.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));

        btnTapCard.addActionListener(e -> onTapCard());

        root.add(btnTapCard, BorderLayout.SOUTH);
        add(root);
    }

    private void onTapCard() {
        btnTapCard.setEnabled(false);
        new SwingWorker<String, Void>() {
            @Override
            protected String doInBackground() throws Exception {
                return cardService.tapCardToSpringBoot();
            }

            @Override
            protected void done() {
                btnTapCard.setEnabled(true);
                try {
                    String uid = get();
                    flashCard("ĐÃ QUÉT THẺ (" + uid + ") -> CHỜ XÁC NHẬN!", false);
                } catch (Exception ex) {
                    String msg = ex.getCause() != null ? ex.getCause().getMessage() : ex.getMessage();
                    flashCard("LỖI GỬI SERVER: " + msg, true);
                }
            }
        }.execute();
    }

    private void flashCard(String text, boolean error) {
        statusText = text;
        isFlashing = true;
        isError = error;
        cardPanel.repaint();

        Timer timer = new Timer(2000, e -> {
            isFlashing = false;
            isError = false;
            statusText = "SẴN SÀNG CHỜ QUÉT (BRIDGE :8088)";
            cardPanel.repaint();
        });
        timer.setRepeats(false);
        timer.start();
    }

    private class CardPanel extends JPanel {
        public CardPanel() {
            setOpaque(false);
        }

        @Override
        protected void paintComponent(Graphics g) {
            super.paintComponent(g);
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

            int w = getWidth();
            int h = getHeight();

            GradientPaint gp = new GradientPaint(
                    0, 0, new Color(30, 58, 110),
                    w, h, new Color(15, 28, 56));
            g2.setPaint(gp);
            g2.fill(new RoundRectangle2D.Double(4, 4, w - 8, h - 8, 28, 28));

            Color borderCol = isError
                    ? new Color(255, 80, 80)
                    : (isFlashing ? new Color(60, 255, 150) : new Color(90, 130, 200, 120));
            g2.setStroke(new BasicStroke(isFlashing ? 3.5f : 1.5f));
            g2.setColor(borderCol);
            g2.draw(new RoundRectangle2D.Double(4, 4, w - 8, h - 8, 28, 28));

            g2.setColor(Color.WHITE);
            g2.setFont(new Font("Arial", Font.BOLD, 16));
            g2.drawString("SMART CARD KHU TRỌ", 24, 38);

            g2.setColor(isFlashing ? new Color(80, 255, 160) : new Color(180, 210, 255));
            g2.setStroke(new BasicStroke(2.2f));
            for (int i = 0; i < 3; i++) {
                int r = 12 + i * 9;
                g2.drawArc(w - 42 - r / 2, 30 - r / 2, r, r, -45, 90);
            }

            g2.setColor(new Color(225, 185, 75));
            g2.fillRoundRect(26, 70, 52, 38, 8, 8);
            g2.setColor(new Color(140, 105, 30));
            g2.setStroke(new BasicStroke(1.2f));
            g2.drawRoundRect(26, 70, 52, 38, 8, 8);
            g2.drawLine(26, 83, 78, 83);
            g2.drawLine(26, 95, 78, 95);
            g2.drawLine(44, 70, 44, 108);
            g2.drawLine(60, 70, 60, 108);

            g2.setColor(new Color(210, 225, 250));
            g2.setFont(new Font("Consolas", Font.BOLD, 16));
            g2.drawString("UID: " + cardService.getActiveCardUid(), 26, 148);

            g2.setColor(isError ? new Color(255, 80, 80) : (isFlashing ? new Color(60, 255, 150) : new Color(0, 190, 255)));
            g2.fillOval(26, h - 36, 11, 11);

            g2.setColor(Color.WHITE);
            g2.setFont(new Font("Arial", Font.BOLD, 12));
            g2.drawString(statusText, 44, h - 26);

            g2.dispose();
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new MainBackendGui().setVisible(true));
    }
}