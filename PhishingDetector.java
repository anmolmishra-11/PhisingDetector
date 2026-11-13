
import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.regex.*;

public class PhishingDetector extends JFrame {

    JTextArea messageArea;
    JTextArea resultArea;
    JLabel scoreLabel;
    JLabel statusLabel;

    public PhishingDetector() {

        setTitle("Suspicious Message & Phishing Detector");
        setSize(700, 600);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);
        setLayout(new BorderLayout(10, 10));

        JLabel heading = new JLabel(
            "Suspicious Message & Phishing Detector",
            SwingConstants.CENTER
        );

        heading.setFont(new Font("Arial", Font.BOLD, 22));
        heading.setBorder(BorderFactory.createEmptyBorder(15, 5, 10, 5));
        add(heading, BorderLayout.NORTH);

        JPanel mainPanel = new JPanel(new BorderLayout(10, 10));
        mainPanel.setBorder(
            BorderFactory.createEmptyBorder(10, 20, 15, 20)
        );

        JLabel inputLabel = new JLabel("Enter your message:");
        inputLabel.setFont(new Font("Arial", Font.BOLD, 15));

        messageArea = new JTextArea(6, 40);
        messageArea.setLineWrap(true);
        messageArea.setWrapStyleWord(true);
        messageArea.setFont(new Font("Arial", Font.PLAIN, 14));

        JScrollPane inputScroll = new JScrollPane(messageArea);

        JButton analyzeButton = new JButton("Analyze Message");
        JButton clearButton = new JButton("Clear");

        JPanel buttonPanel = new JPanel();
        buttonPanel.add(analyzeButton);
        buttonPanel.add(clearButton);

        scoreLabel = new JLabel("Risk Score: --");
        scoreLabel.setFont(new Font("Arial", Font.BOLD, 18));

        statusLabel = new JLabel("Waiting for message...");
        statusLabel.setFont(new Font("Arial", Font.BOLD, 16));

        resultArea = new JTextArea(10, 40);
        resultArea.setEditable(false);
        resultArea.setLineWrap(true);
        resultArea.setWrapStyleWord(true);
        resultArea.setFont(new Font("Arial", Font.PLAIN, 14));

        JScrollPane resultScroll = new JScrollPane(resultArea);

        JPanel topPanel = new JPanel(new BorderLayout(5, 5));
        topPanel.add(inputLabel, BorderLayout.NORTH);
        topPanel.add(inputScroll, BorderLayout.CENTER);
        topPanel.add(buttonPanel, BorderLayout.SOUTH);

        JPanel bottomPanel = new JPanel(new BorderLayout(5, 10));
        bottomPanel.add(scoreLabel, BorderLayout.NORTH);
        bottomPanel.add(resultScroll, BorderLayout.CENTER);
        bottomPanel.add(statusLabel, BorderLayout.SOUTH);

        mainPanel.add(topPanel, BorderLayout.NORTH);
        mainPanel.add(bottomPanel, BorderLayout.CENTER);

        add(mainPanel, BorderLayout.CENTER);

        analyzeButton.addActionListener(e -> analyzeMessage());

        clearButton.addActionListener(e -> {
            messageArea.setText("");
            resultArea.setText("");
            scoreLabel.setText("Risk Score: --");
            statusLabel.setText("Waiting for message...");
            statusLabel.setForeground(Color.BLACK);
        });

        setVisible(true);
    }

    void analyzeMessage() {

        String message = messageArea.getText().toLowerCase();

        if (message.trim().isEmpty()) {
            JOptionPane.showMessageDialog(
                this, "Please enter a message first!"
            );
            return;
        }

        int score = 0;

        ArrayList<String> reasons = new ArrayList<>();

        // Rule 1: Urgent language
        String[] urgency = {
            "urgent", "immediately", "act now",
            "within 24 hours", "limited time"
        };

        for (String word : urgency) {
            if (message.contains(word)) {
                score += 15;
                reasons.add("Urgent language detected: " + word);
                break;
            }
        }

        // Rule 2: Sensitive information requests
        String[] sensitive = {
            "password", "otp", "pin", "cvv",
            "bank details", "credit card"
        };

        for (String word : sensitive) {
            if (message.contains(word)) {
                score += 25;
                reasons.add("Sensitive information requested: " + word);
                break;
            }
        }

        // Rule 3: Prize and reward messages
        String[] prizes = {
            "won", "winner", "lottery",
            "prize", "reward", "free gift"
        };

        for (String word : prizes) {
            if (message.contains(word)) {
                score += 20;
                reasons.add("Suspicious prize or reward claim: " + word);
                break;
            }
        }

        // Rule 4: Threatening language
        String[] threats = {
            "blocked", "suspended", "terminated",
            "account closed", "legal action"
        };

        for (String word : threats) {
            if (message.contains(word)) {
                score += 20;
                reasons.add("Threatening language detected: " + word);
                break;
            }
        }

        // Rule 5: Click requests
        String[] clickWords = {
            "click here", "click this link",
            "verify now", "login here"
        };

        for (String word : clickWords) {
            if (message.contains(word)) {
                score += 15;
                reasons.add("Suspicious action requested: " + word);
                break;
            }
        }

        // Rule 6: Suspicious URL patterns
        Pattern urlPattern = Pattern.compile(
            "(https?://|www\\.)\\S+",
            Pattern.CASE_INSENSITIVE
        );

        Matcher matcher = urlPattern.matcher(message);

        while (matcher.find()) {

            String url = matcher.group().toLowerCase();

            if (url.contains("bit.ly") ||
                url.contains("tinyurl.com") ||
                url.contains("is.gd") ||
                url.contains("tiny.cc") ||
                url.matches(".*https?://\\d{1,3}(\\.\\d{1,3}){3}.*")) {

                score += 25;
                reasons.add("Suspicious URL pattern detected: " + url);
                break;
            }
        }

        // Rule 7: General request for a link
        if (message.contains("link") &&
            matcher.reset().find() == false &&
            reasons.stream().noneMatch(
                r -> r.startsWith("Suspicious action requested")
            )) {
            // No additional points for a generic mention of a link.
        }

        // Maximum risk score is 100
        score = Math.min(score, 100);

        scoreLabel.setText("Risk Score: " + score + "/100");

        resultArea.setText("");

        if (reasons.isEmpty()) {
            resultArea.setText(
                "No suspicious patterns detected.\n" +
                "This does not guarantee that the message is safe."
            );
        } else {
            resultArea.append("Suspicious indicators found:\n\n");

            for (String reason : reasons) {
                resultArea.append("• " + reason + "\n");
            }
        }

        if (score >= 60) {
            statusLabel.setText("HIGH RISK - Potential Phishing Message");
            statusLabel.setForeground(Color.RED);
        }
        else if (score >= 30) {
            statusLabel.setText("SUSPICIOUS - Be Careful");
            statusLabel.setForeground(Color.ORANGE);
        }
        else {
            statusLabel.setText("LOW RISK - No major indicators found");
            statusLabel.setForeground(new Color(0, 130, 0));
        }
    }

    public static void main(String[] args) {

        SwingUtilities.invokeLater(() -> {
            new PhishingDetector();
        });
    }
}
