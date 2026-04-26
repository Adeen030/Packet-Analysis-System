/* 
    =========================Network Packet Analyzer(Betat-Version)============================
    ===============Collaborators===============================================
    ==========Adeen Khan========================================
    ==========Abdul Saboor Hasan================================
    ==========Anas Imran========================================
*/

#include <iostream>
#include <string>
using namespace std;

// ========================== PACKET ==========================
struct Packet {
    int id;
    string sourceIP;
    string destIP;
    string protocol;
    int priority;
    string data;
};

// ========================== STRING SEARCH ==========================
bool contains(string text, string keyword) {
    int n = text.length();
    int m = keyword.length();

    for (int i = 0; i <= n - m; i++) {
        int j = 0;

        while (j < m && text[i + j] == keyword[j]) {
            j++;
        }

        if (j == m)
            return true;
    }

    return false;
}

// ========================== IDS SCORING SYSTEM ==========================
int calculateRisk(Packet p) {
    int score = 0;

    if (p.sourceIP == "0.0.0.0")
        score += 40;

    if (contains(p.protocol, "UNKNOWN"))
        score += 25;

    if (contains(p.data, "attack"))
        score += 30;

    if (contains(p.data, "hack"))
        score += 30;

    if (contains(p.data, "virus"))
        score += 20;

    return score;
}

string classifyRisk(int score) {
    if (score >= 80)
        return "CRITICAL ATTACK";
    else if (score >= 60)
        return "HIGH RISK";
    else if (score >= 30)
        return "MEDIUM RISK";
    else
        return "SAFE";
}

// ========================== PRIORITY QUEUE ==========================
class PacketQueue {
private:
    Packet arr[100];
    int size;

public:
    PacketQueue() { size = 0; }

    bool isEmpty() { return size == 0; }

    bool isFull() { return size == 100; }

    void enqueue(Packet p) {
        if (isFull()) {
            cout << "Queue Overflow! Packet dropped.\n";
            return;
        }

        int i = size - 1;

        while (i >= 0 && arr[i].priority > p.priority) {
            arr[i + 1] = arr[i];
            i--;
        }

        arr[i + 1] = p;
        size++;
    }

    Packet dequeue() {
        if (isEmpty()) return {-1,"","","",0,""};

        Packet p = arr[0];

        for (int i = 0; i < size - 1; i++)
            arr[i] = arr[i + 1];

        size--;

        return p;
    }

    void display() {
        cout << "\n===== Packet Queue =====\n";

        if (isEmpty()) {
            cout << "Queue empty.\n";
            return;
        }

        for (int i = 0; i < size; i++) {
            cout << arr[i].id << " | "
                 << arr[i].sourceIP << " -> "
                 << arr[i].destIP << " | "
                 << arr[i].protocol << " | "
                 << arr[i].data << " | P:" << arr[i].priority << endl;
        }
    }
};

// ========================== STACK ==========================
class ProtocolStack {
private:
    string arr[10];
    int top;

public:
    ProtocolStack() { top = -1; }

    void push(string x) { if (top < 9) arr[++top] = x; }

    string pop() { return (top >= 0) ? arr[top--] : ""; }

    bool isEmpty() { return top == -1; }
};

// ========================== NORMAL LOGS (LINKED LIST) ==========================
class LogNode {
public:
    Packet data;
    LogNode* next;

    LogNode(Packet p) {
        data = p;
        next = NULL;
    }
};

class PacketLog {
private:
    LogNode* head;

public:
    PacketLog() { head = NULL; }

    void add(Packet p) {
        LogNode* nn = new LogNode(p);

        if (!head) head = nn;
        else {
            LogNode* temp = head;
            while (temp->next)
                temp = temp->next;
            temp->next = nn;
        }
    }

    void display() {
        cout << "\n===== Processed Packet Logs =====\n";

        if (!head) {
            cout << "No logs.\n";
            return;
        }

        LogNode* temp = head;

        while (temp) {
            cout << temp->data.id << " | "
                 << temp->data.sourceIP << " -> "
                 << temp->data.destIP << " | "
                 << temp->data.protocol << " | "
                 << temp->data.data << endl;

            temp = temp->next;
        }
    }
};

// ========================== SUSPICIOUS LOGS ==========================
class SuspiciousNode {
public:
    Packet data;
    string reason;
    SuspiciousNode* next;

    SuspiciousNode(Packet p, string r) {
        data = p;
        reason = r;
        next = NULL;
    }
};

class SuspiciousLog {
private:
    SuspiciousNode* head;

public:
    SuspiciousLog() { head = NULL; }

    void add(Packet p, string reason) {
        SuspiciousNode* nn = new SuspiciousNode(p, reason);

        if (!head) head = nn;
        else {
            SuspiciousNode* temp = head;
            while (temp->next)
                temp = temp->next;
            temp->next = nn;
        }
    }

    void display() {
        cout << "\n===== Suspicious Packet Logs =====\n";

        if (!head) {
            cout << "No suspicious packets.\n";
            return;
        }

        SuspiciousNode* temp = head;

        while (temp) {
            cout << temp->data.id << " | "
                 << temp->data.sourceIP << " -> "
                 << temp->data.destIP
                 << " | Risk: " << temp->reason
                 << " | Data: " << temp->data.data << endl;

            temp = temp->next;
        }
    }
};

// ========================== SUSPICIOUS IPs ==========================
class SuspiciousIPs {
private:
    string ips[100];
    int count;

public:
    SuspiciousIPs() { count = 0; }

    bool exists(string ip) {
        for (int i = 0; i < count; i++)
            if (ips[i] == ip) return true;
        return false;
    }

    void add(string ip) {
        if (!exists(ip))
            ips[count++] = ip;
    }

    void display() {
        cout << "\n===== Suspicious IPs =====\n";

        if (count == 0) {
            cout << "None detected.\n";
            return;
        }

        for (int i = 0; i < count; i++)
            cout << ips[i] << endl;
    }
};

// ========================== ANALYZER ==========================
void analyzeProtocol(string protocol) {
    ProtocolStack st;
    string temp = "";

    for (int i = 0; i < protocol.length(); i++) {
        if (protocol[i] == '>') {
            st.push(temp);
            temp = "";
        } else temp += protocol[i];
    }
    st.push(temp);

    cout << "\n===== Protocol Analysis =====\n";

    while (!st.isEmpty()) {
        string layer = st.pop();

        cout << layer << " -> ";

        if (layer == "ETH")
            cout << "MAC Layer";
        else if (layer == "IP")
            cout << "Routing Layer";
        else if (layer == "TCP")
            cout << "Reliable Transfer";
        else if (layer == "HTTP")
            cout << "Web Layer";
        else
            cout << "Unknown";

        cout << endl;
    }
}

// ========================== MAIN ==========================
int main() {
    PacketQueue queue;
    PacketLog log;
    SuspiciousLog slog;
    SuspiciousIPs sip;

    int choice, id = 1;

    do {
        cout << "\n====== IDS Packet Analyzer ======\n";
        cout << "1. Generate Packet\n";
        cout << "2. View Queue\n";
        cout << "3. Process Packet\n";
        cout << "4. View Logs\n";
        cout << "5. View Suspicious IPs\n";
        cout << "6. View Suspicious Packet Logs\n";
        cout << "7. Exit\n";
        cout << "Enter choice: ";
        cin >> choice;

        if (choice == 1) {
            Packet p;
            p.id = id++;

            cout << "Source IP: ";
            cin >> p.sourceIP;

            cout << "Dest IP: ";
            cin >> p.destIP;

            cout << "Protocol: (Format : ETH>IP>TCP>HTTP) ";
            cin >> p.protocol;

            cout << "Priority (1-3): ";
            cin >> p.priority;

            cin.ignore();
            cout << "Data: ";
            getline(cin, p.data);

            queue.enqueue(p);
        }

        else if (choice == 2) {
            queue.display();
        }

        else if (choice == 3) {
            Packet p = queue.dequeue();

            if (p.id != -1) {
                cout << "\nProcessing Packet ID: " << p.id << endl;

                analyzeProtocol(p.protocol);
                log.add(p);

                int risk = calculateRisk(p);
                string level = classifyRisk(risk);

                cout << "\n--- IDS REPORT ---\n";
                cout << "Risk Score: " << risk << "/100\n";
                cout << "Status: " << level << endl;

                if (risk >= 60) {
                    cout << "ALERT: Threat Detected!\n";
                    sip.add(p.sourceIP);
                    slog.add(p, level);
                }
            }
        }

        else if (choice == 4) {
            log.display();
        }

        else if (choice == 5) {
            sip.display();
        }

        else if (choice == 6) {
            slog.display();
        }

    } while (choice != 7);

    return 0;
}
