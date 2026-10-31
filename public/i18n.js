(() => {
  const messages = {
    en: {
      languageLabel: "Language", pageTitle: "ClearSignal — Website safety check", pageDescription: "Check a website address for phishing and look-alike warning signs before you visit.", privacy: "Local-first checks", how: "How it works",
      eyebrow: "A clearer way to check a link", headline: "Spot the fake<br>before you <span class=\"headline-accent\">click.</span>",
      intro: "Look-alike websites can fool anyone. Check an address for known phishing reports and suspicious clues—in plain language, before you visit.",
      chipChecked: "Address checked", chipControl: "You stay in control",
      checkerTitle: "Check a website address", checkerSubtitle: "Address checks are private. Live page checks require your opt-in.",
      urlLabel: "Website address", urlPlaceholder: "Paste a website address, e.g. https://example.com", clear: "Clear address", check: "Check address", checking: "Checking…",
      hint: "Without live inspection, the submitted URL is checked locally and against public threat data.",
      network: "Inspect the public site (TLS, redirects, DNS and HTML) <span class=\"network-option-note\">(contacts the site; may follow up to 3 redirects)</span>",
      sectionKicker: "SIMPLE. TRANSPARENT. USEFUL.", sectionTitle: "Know what raised a flag.", sectionIntro: "No mystery score. Every check comes with a human-readable explanation.",
      step1Title: "Check public reports", step1: "Compare the address with the OpenPhish community feed of reported phishing sites.",
      step2Title: "Look for copycats", step2: "Spot brand names on unrelated domains, deceptive address patterns, and other warning signs.",
      step3Title: "Stay in control", step3: "Get a clear explanation without visiting the address or sending it to the destination site.",
      detail1Title: "What does a scan check?", detail1: "Every scan checks the address for known phishing reports, brand look-alikes, deceptive characters, suspicious URL patterns, and other signals. Each warning appears below the score with its category and explanation.",
      detail2Title: "What happens during a live check?", detail2: "Live inspection is optional and off by default. When you opt in, ClearSignal checks the public site's TLS certificate, redirects, DNS, domain age, and a limited amount of page HTML. It does not run the site's JavaScript.",
      detail3Title: "What does the result mean?", detail3: "Scores below 8 are labeled safe, 8–69 suspicious, and 70 or higher blocked by this app. These are heuristic signals, not certainty: sites can be missed or flagged by mistake.",
      detail4Title: "What does “blocked” do?", detail4: "High-scoring domains are added to ClearSignal's local blocklist and flagged in later scans. The app does not change your browser, operating system, or network settings. Hosts-file rules are only downloaded for your review.",
      reportTitle: "Found a problem or a false alarm?", reportText: "Report a bug or suggest an improvement on GitHub. Include what you expected and what happened; remove private URLs or personal information before sharing.", report: "Report a problem",
      noteTitle: "A helpful signal, not a guarantee.", note: "New or unreported threats may not appear in public feeds. When in doubt, use a saved bookmark or type the official address yourself.",
      chatToggle: "Need help?", chatTitle: "ClearSignal assistant", chatSubtitle: "Help with the app and safer browsing",
      chatPrivacy: "Messages are handled by this app locally and are not sent to an AI provider.",
      chatWelcome: "Hi! I can show you how to check an address, explain scan results, or guide you around ClearSignal. What would you like help with?",
      suggestion1: "How do I check a website address?", suggestionLabel1: "How do I check a link?",
      suggestion2: "What does the score mean?", suggestionLabel2: "What does the score mean?",
      suggestion3: "What is live inspection?", suggestionLabel3: "What is live inspection?",
      chatInputLabel: "Ask ClearSignal assistant", chatPlaceholder: "Ask a question…", send: "Send", footer: "Made to help you browse with confidence.",
      pasteAddress: "Paste a website address to get started.", checkerFailed: "Could not reach the checker. Please try again.",
      unavailable: "The assistant isn’t available right now. Try again in a moment.", checkingAvailability: "Checking assistant availability…",
      replying: "The assistant is replying…", localAnswered: "Answered by the local ClearSignal assistant.",
      assistantReady: "The assistant is ready.", localReady: "The local help assistant is ready.",
      chatUnavailable: "Chat is unavailable right now.", healthFailed: "Could not check assistant availability.",
      blockedHeading: "Malicious indicators detected", suspiciousHeading: "Suspicious signals detected", safeHeading: "No strong threat signals",
      blockedExplain: "Strong indicators crossed the local blocking threshold.", suspiciousExplain: "Review the findings before you continue.",
      safeExplain: "No high-confidence warning indicators were found. This is not a guarantee.",
      blockedBanner: "WEBSITE BLOCKED", blockedInfo: "This domain was added to ClearSignal’s local blocklist. No changes were made to your operating system or browser.",
      viewBlocklist: "View local blocklist", downloadRules: "Download hosts-file rules", score: "CLEARSIGNAL THREAT SCORE",
      analysis: "ANALYSIS REPORT", reportHeading: "What’s Wrong With This Website", finding: "finding", findings: "findings",
      category: "Category", severity: "Severity", issue: "Finding", penalty: "Penalty", noFlags: "No warning flags were triggered. A low score is not a guarantee of safety.",
      tlsIssuer: "TLS issuer:", certExpires: "Certificate expires in", certAge: "Certificate age",
      pageUnavailable: "Page inspection unavailable:", liveUnavailable: "Live check unavailable:",
      localReply: "I can help with checking an address, understanding its warning score, or using optional live inspection. Paste a website address into the main box and select Check address.",
      disclaimer: "Automated URL checks can produce false positives and cannot guarantee safety.", action: "Action:",
      threatIntel: "Threat intelligence:", urlHeuristics: "URL heuristics", aboutOpenPhish: "About OpenPhish",
      scoreAria: "Threat score {score} out of 100", formInvalid: "Unable to check this address."
    },
    te: {
      languageLabel: "భాష", pageTitle: "ClearSignal — వెబ్‌సైట్ భద్రత తనిఖీ", pageDescription: "సందర్శించే ముందు ఫిషింగ్ మరియు నకిలీ వెబ్‌సైట్ సంకేతాల కోసం చిరునామాను తనిఖీ చేయండి.", privacy: "స్థానికంగా ప్రైవేట్ తనిఖీలు", how: "ఇది ఎలా పనిచేస్తుంది",
      eyebrow: "లింక్‌ను స్పష్టంగా తనిఖీ చేయండి", headline: "నకిలీని గుర్తించండి<br>క్లిక్ <span class=\"headline-accent\">చేయకముందే.</span>",
      intro: "నకిలీ వెబ్‌సైట్‌లు ఎవరినైనా మోసం చేయవచ్చు. సందర్శించే ముందు ఫిషింగ్ నివేదికలు, అనుమానాస్పద సంకేతాల కోసం చిరునామాను తనిఖీ చేయండి.",
      chipChecked: "చిరునామా తనిఖీ అయింది", chipControl: "నియంత్రణ మీ చేతిలోనే",
      checkerTitle: "వెబ్‌సైట్ చిరునామాను తనిఖీ చేయండి", checkerSubtitle: "చిరునామా తనిఖీలు ప్రైవేట్. ప్రత్యక్ష తనిఖీకి మీ అనుమతి అవసరం.",
      urlLabel: "వెబ్‌సైట్ చిరునామా", urlPlaceholder: "వెబ్‌సైట్ చిరునామాను అతికించండి, ఉదా: https://example.com", clear: "చిరునామాను తొలగించండి", check: "చిరునామా తనిఖీ", checking: "తనిఖీ చేస్తోంది…",
      hint: "ప్రత్యక్ష తనిఖీ లేకుండా, URL స్థానికంగా మరియు పబ్లిక్ బెదిరింపు సమాచారంతో తనిఖీ చేయబడుతుంది.",
      network: "పబ్లిక్ సైట్‌ను తనిఖీ చేయండి (TLS, రీడైరెక్ట్‌లు, DNS, HTML) <span class=\"network-option-note\">(సైట్‌ను సంప్రదిస్తుంది; గరిష్ఠంగా 3 రీడైరెక్ట్‌లు)</span>",
      sectionKicker: "సరళం. పారదర్శకం. ఉపయోగకరం.", sectionTitle: "హెచ్చరికకు కారణం తెలుసుకోండి.", sectionIntro: "అర్థంకాని స్కోర్‌లు లేవు. ప్రతి తనిఖీకి స్పష్టమైన వివరణ ఉంటుంది.",
      step1Title: "పబ్లిక్ నివేదికలను తనిఖీ చేయండి", step1: "నివేదించబడిన ఫిషింగ్ సైట్‌ల OpenPhish ఫీడ్‌తో చిరునామాను పోల్చండి.",
      step2Title: "నకిలీలను గుర్తించండి", step2: "సంబంధం లేని డొమైన్‌లలో బ్రాండ్ పేర్లు, మోసపూరిత చిరునామాలు, ఇతర హెచ్చరికలను గుర్తించండి.",
      step3Title: "నియంత్రణ మీ చేతిలో ఉంచుకోండి", step3: "సైట్‌ను సందర్శించకుండా లేదా దానికి డేటా పంపకుండా స్పష్టమైన వివరణ పొందండి.",
      detail1Title: "స్కాన్ ఏమి తనిఖీ చేస్తుంది?", detail1: "తెలిసిన ఫిషింగ్ నివేదికలు, నకిలీ బ్రాండ్‌లు, మోసపూరిత అక్షరాలు, అనుమానాస్పద URL నమూనాలు మరియు ఇతర సంకేతాల కోసం చిరునామాను తనిఖీ చేస్తుంది. ప్రతి హెచ్చరిక స్కోర్ కింద కనిపిస్తుంది.",
      detail2Title: "ప్రత్యక్ష తనిఖీలో ఏమి జరుగుతుంది?", detail2: "ప్రత్యక్ష తనిఖీ ఐచ్ఛికం; డిఫాల్ట్‌గా ఆఫ్‌లో ఉంటుంది. మీరు అనుమతిస్తే, TLS సర్టిఫికేట్, రీడైరెక్ట్‌లు, DNS, డొమైన్ వయస్సు, కొంత HTML తనిఖీ చేస్తుంది. సైట్ JavaScript‌ను అమలు చేయదు.",
      detail3Title: "ఫలితం అర్థం ఏమిటి?", detail3: "8 కంటే తక్కువ స్కోర్లు సురక్షితం, 8–69 అనుమానాస్పదం, 70 లేదా అంతకంటే ఎక్కువ ఈ యాప్‌లో బ్లాక్ చేయబడతాయి. ఇవి అంచనా సంకేతాలు మాత్రమే; పొరపాట్లు జరగవచ్చు.",
      detail4Title: "“బ్లాక్” అంటే ఏమిటి?", detail4: "అధిక స్కోర్ ఉన్న డొమైన్‌లు ClearSignal స్థానిక బ్లాక్‌లిస్ట్‌లో చేరతాయి. యాప్ మీ బ్రౌజర్, ఆపరేటింగ్ సిస్టమ్ లేదా నెట్‌వర్క్ సెట్టింగ్‌లను మార్చదు. Hosts ఫైల్ నియమాలు మీ సమీక్ష కోసం మాత్రమే డౌన్‌లోడ్ అవుతాయి.",
      reportTitle: "సమస్య లేదా తప్పుడు హెచ్చరిక కనిపించిందా?", reportText: "GitHubలో లోపాన్ని నివేదించండి లేదా మెరుగుదల సూచించండి. ప్రైవేట్ URLలు లేదా వ్యక్తిగత సమాచారాన్ని తొలగించండి.", report: "సమస్యను నివేదించండి",
      noteTitle: "ఇది ఉపయోగకరమైన సూచన మాత్రమే; హామీ కాదు.", note: "కొత్త లేదా నివేదించని బెదిరింపులు పబ్లిక్ ఫీడ్‌లలో ఉండకపోవచ్చు. సందేహం ఉంటే, బుక్‌మార్క్ లేదా అధికారిక చిరునామాను ఉపయోగించండి.",
      chatToggle: "సహాయం కావాలా?", chatTitle: "ClearSignal సహాయకుడు", chatSubtitle: "యాప్ మరియు సురక్షిత బ్రౌజింగ్ సహాయం",
      chatPrivacy: "సందేశాలు ఈ యాప్‌లోనే స్థానికంగా నిర్వహించబడతాయి; AI సేవకు పంపబడవు.",
      chatWelcome: "నమస్తే! చిరునామాను తనిఖీ చేయడం, స్కాన్ ఫలితాలను అర్థం చేసుకోవడం లేదా ClearSignal ఉపయోగించడంలో సహాయం చేస్తాను. మీకు ఏం కావాలి?",
      suggestion1: "వెబ్‌సైట్ చిరునామాను ఎలా తనిఖీ చేయాలి?", suggestionLabel1: "లింక్‌ను ఎలా తనిఖీ చేయాలి?",
      suggestion2: "స్కోర్ అర్థం ఏమిటి?", suggestionLabel2: "స్కోర్ అర్థం ఏమిటి?",
      suggestion3: "ప్రత్యక్ష తనిఖీ అంటే ఏమిటి?", suggestionLabel3: "ప్రత్యక్ష తనిఖీ ఏమిటి?",
      chatInputLabel: "ClearSignal సహాయకుడిని అడగండి", chatPlaceholder: "ప్రశ్న అడగండి…", send: "పంపండి", footer: "నమ్మకంగా బ్రౌజ్ చేయడంలో మీకు సహాయం చేయడానికి.",
      pasteAddress: "ప్రారంభించడానికి వెబ్‌సైట్ చిరునామాను అతికించండి.", checkerFailed: "తనిఖీ సేవను చేరుకోలేకపోయాం. మళ్లీ ప్రయత్నించండి.",
      unavailable: "సహాయకుడు ప్రస్తుతం అందుబాటులో లేరు. కొద్దిసేపటి తర్వాత ప్రయత్నించండి.", checkingAvailability: "సహాయకుడి లభ్యతను తనిఖీ చేస్తోంది…",
      replying: "సహాయకుడు సమాధానం ఇస్తున్నారు…", localAnswered: "ClearSignal స్థానిక సహాయకుడి సమాధానం.",
      assistantReady: "సహాయకుడు సిద్ధంగా ఉన్నారు.", localReady: "స్థానిక సహాయకుడు సిద్ధంగా ఉన్నారు.",
      chatUnavailable: "చాట్ ప్రస్తుతం అందుబాటులో లేదు.", healthFailed: "సహాయకుడి లభ్యతను తనిఖీ చేయలేకపోయాం.",
      blockedHeading: "హానికర సంకేతాలు గుర్తించబడ్డాయి", suspiciousHeading: "అనుమానాస్పద సంకేతాలు గుర్తించబడ్డాయి", safeHeading: "బలమైన ముప్పు సంకేతాలు లేవు",
      blockedExplain: "బలమైన సంకేతాలు స్థానిక బ్లాకింగ్ పరిమితిని దాటాయి.", suspiciousExplain: "కొనసాగించే ముందు ఫలితాలను పరిశీలించండి.",
      safeExplain: "అధిక నమ్మకంతో కూడిన హెచ్చరికలు లేవు. ఇది భద్రతకు హామీ కాదు.",
      blockedBanner: "వెబ్‌సైట్ బ్లాక్ చేయబడింది", blockedInfo: "ఈ డొమైన్ ClearSignal స్థానిక బ్లాక్‌లిస్ట్‌లో చేర్చబడింది. మీ పరికరంలో ఎలాంటి మార్పులు చేయలేదు.",
      viewBlocklist: "స్థానిక బ్లాక్‌లిస్ట్ చూడండి", downloadRules: "Hosts నియమాలను డౌన్‌లోడ్ చేయండి", score: "CLEARSIGNAL ముప్పు స్కోర్",
      analysis: "విశ్లేషణ నివేదిక", reportHeading: "ఈ వెబ్‌సైట్‌లో ఏమి సమస్య?", finding: "సంకేతం", findings: "సంకేతాలు",
      category: "వర్గం", severity: "తీవ్రత", issue: "కనుగొన్నది", penalty: "పెనాల్టీ", noFlags: "హెచ్చరిక సంకేతాలు లేవు. తక్కువ స్కోర్ భద్రతకు హామీ కాదు.",
      tlsIssuer: "TLS జారీదారు:", certExpires: "సర్టిఫికేట్ గడువు", certAge: "సర్టిఫికేట్ వయస్సు",
      pageUnavailable: "పేజీ తనిఖీ అందుబాటులో లేదు:", liveUnavailable: "ప్రత్యక్ష తనిఖీ అందుబాటులో లేదు:",
      localReply: "చిరునామా తనిఖీ, హెచ్చరిక స్కోర్ అర్థం చేసుకోవడం లేదా ఐచ్ఛిక ప్రత్యక్ష తనిఖీని ఉపయోగించడంలో సహాయం చేస్తాను. ప్రధాన బాక్స్‌లో చిరునామాను అతికించి, చిరునామా తనిఖీని ఎంచుకోండి.",
      disclaimer: "ఆటోమేటిక్ URL తనిఖీల్లో పొరపాట్లు ఉండవచ్చు; భద్రతకు హామీ ఇవ్వలేవు.", action: "చర్య:",
      threatIntel: "ముప్పు సమాచారం:", urlHeuristics: "URL అంచనా తనిఖీలు", aboutOpenPhish: "OpenPhish గురించి",
      scoreAria: "100లో ముప్పు స్కోర్ {score}", formInvalid: "ఈ చిరునామాను తనిఖీ చేయలేకపోయాం."
    },
    hi: {
      languageLabel: "भाषा", pageTitle: "ClearSignal — वेबसाइट सुरक्षा जाँच", pageDescription: "खोलने से पहले फ़िशिंग और नकली वेबसाइट के संकेतों के लिए पता जाँचें।", privacy: "स्थानीय और निजी जाँच", how: "यह कैसे काम करता है",
      eyebrow: "लिंक जाँचने का आसान तरीका", headline: "नकली पहचानें<br>क्लिक <span class=\"headline-accent\">करने से पहले।</span>",
      intro: "नकली वेबसाइट किसी को भी धोखा दे सकती हैं। खोलने से पहले फ़िशिंग रिपोर्ट और संदिग्ध संकेतों के लिए पता जाँचें।",
      chipChecked: "पता जाँचा गया", chipControl: "नियंत्रण आपके हाथ में",
      checkerTitle: "वेबसाइट का पता जाँचें", checkerSubtitle: "पते की जाँच निजी है। लाइव जाँच के लिए आपकी सहमति ज़रूरी है।",
      urlLabel: "वेबसाइट का पता", urlPlaceholder: "वेबसाइट का पता पेस्ट करें, जैसे https://example.com", clear: "पता साफ़ करें", check: "पता जाँचें", checking: "जाँच जारी…",
      hint: "लाइव जाँच के बिना, URL स्थानीय रूप से और सार्वजनिक ख़तरा डेटा से जाँचा जाता है।",
      network: "सार्वजनिक साइट जाँचें (TLS, रीडायरेक्ट, DNS और HTML) <span class=\"network-option-note\">(साइट से संपर्क होगा; अधिकतम 3 रीडायरेक्ट)</span>",
      sectionKicker: "सरल। पारदर्शी। उपयोगी।", sectionTitle: "जानें चेतावनी क्यों मिली।", sectionIntro: "कोई रहस्यमय स्कोर नहीं। हर जाँच के साथ साफ़ व्याख्या मिलती है।",
      step1Title: "सार्वजनिक रिपोर्ट जाँचें", step1: "पते की तुलना रिपोर्ट की गई फ़िशिंग साइटों की OpenPhish फ़ीड से करें।",
      step2Title: "नकली साइट पहचानें", step2: "असंबंधित डोमेन में ब्रांड नाम, भ्रामक पते और अन्य चेतावनी संकेत पहचानें।",
      step3Title: "नियंत्रण अपने हाथ में रखें", step3: "साइट खोले या उसे डेटा भेजे बिना स्पष्ट जानकारी पाएँ।",
      detail1Title: "स्कैन क्या जाँचता है?", detail1: "हर स्कैन ज्ञात फ़िशिंग रिपोर्ट, मिलते-जुलते ब्रांड, भ्रामक अक्षर, संदिग्ध URL पैटर्न और अन्य संकेत जाँचता है। हर चेतावनी स्कोर के नीचे दिखाई जाती है।",
      detail2Title: "लाइव जाँच में क्या होता है?", detail2: "लाइव जाँच वैकल्पिक है और डिफ़ॉल्ट रूप से बंद रहती है। सहमति देने पर ClearSignal सार्वजनिक साइट का TLS प्रमाणपत्र, रीडायरेक्ट, DNS, डोमेन की उम्र और सीमित HTML जाँचता है। साइट का JavaScript नहीं चलाता।",
      detail3Title: "परिणाम का क्या अर्थ है?", detail3: "8 से कम स्कोर सुरक्षित, 8–69 संदिग्ध और 70 या अधिक इस ऐप में ब्लॉक होते हैं। ये अनुमानित संकेत हैं; परिणाम गलत भी हो सकते हैं।",
      detail4Title: "“ब्लॉक” करने से क्या होता है?", detail4: "ज़्यादा स्कोर वाले डोमेन ClearSignal की स्थानीय ब्लॉकलिस्ट में जुड़ते हैं। ऐप आपके ब्राउज़र, ऑपरेटिंग सिस्टम या नेटवर्क सेटिंग नहीं बदलता। Hosts फ़ाइल नियम केवल समीक्षा के लिए डाउनलोड होते हैं।",
      reportTitle: "कोई समस्या या गलत चेतावनी मिली?", reportText: "GitHub पर बग बताएँ या सुधार सुझाएँ। साझा करने से पहले निजी URL और व्यक्तिगत जानकारी हटा दें।", report: "समस्या बताएँ",
      noteTitle: "यह उपयोगी संकेत है, सुरक्षा की गारंटी नहीं।", note: "नई या रिपोर्ट न की गई धमकियाँ सार्वजनिक फ़ीड में नहीं दिख सकतीं। संदेह हो तो सहेजे गए बुकमार्क या आधिकारिक पते का उपयोग करें।",
      chatToggle: "मदद चाहिए?", chatTitle: "ClearSignal सहायक", chatSubtitle: "ऐप और सुरक्षित ब्राउज़िंग में मदद",
      chatPrivacy: "संदेश इस ऐप में स्थानीय रूप से संभाले जाते हैं और किसी AI सेवा को नहीं भेजे जाते।",
      chatWelcome: "नमस्ते! मैं पता जाँचने, स्कैन परिणाम समझने या ClearSignal इस्तेमाल करने में मदद कर सकता हूँ। आपको किस चीज़ में मदद चाहिए?",
      suggestion1: "वेबसाइट का पता कैसे जाँचें?", suggestionLabel1: "लिंक कैसे जाँचें?",
      suggestion2: "स्कोर का क्या अर्थ है?", suggestionLabel2: "स्कोर का अर्थ क्या है?",
      suggestion3: "लाइव जाँच क्या है?", suggestionLabel3: "लाइव जाँच क्या है?",
      chatInputLabel: "ClearSignal सहायक से पूछें", chatPlaceholder: "कोई सवाल पूछें…", send: "भेजें", footer: "आत्मविश्वास से ब्राउज़ करने में आपकी मदद के लिए।",
      pasteAddress: "शुरू करने के लिए वेबसाइट का पता पेस्ट करें।", checkerFailed: "जाँच सेवा तक नहीं पहुँच सके। फिर कोशिश करें।",
      unavailable: "सहायक अभी उपलब्ध नहीं है। थोड़ी देर बाद कोशिश करें।", checkingAvailability: "सहायक की उपलब्धता जाँच रहे हैं…",
      replying: "सहायक जवाब दे रहा है…", localAnswered: "ClearSignal के स्थानीय सहायक का जवाब।",
      assistantReady: "सहायक तैयार है।", localReady: "स्थानीय सहायक तैयार है।",
      chatUnavailable: "चैट अभी उपलब्ध नहीं है।", healthFailed: "सहायक की उपलब्धता जाँच नहीं सके।",
      blockedHeading: "हानिकारक संकेत मिले", suspiciousHeading: "संदिग्ध संकेत मिले", safeHeading: "खतरे के मज़बूत संकेत नहीं",
      blockedExplain: "मज़बूत संकेत स्थानीय ब्लॉक सीमा से ऊपर थे।", suspiciousExplain: "आगे बढ़ने से पहले नतीजे देखें।",
      safeExplain: "विश्वसनीय चेतावनी संकेत नहीं मिले। यह सुरक्षा की गारंटी नहीं है।",
      blockedBanner: "वेबसाइट ब्लॉक की गई", blockedInfo: "यह डोमेन ClearSignal की स्थानीय ब्लॉकलिस्ट में जोड़ा गया। आपके डिवाइस में कोई बदलाव नहीं किया गया।",
      viewBlocklist: "स्थानीय ब्लॉकलिस्ट देखें", downloadRules: "Hosts नियम डाउनलोड करें", score: "CLEARSIGNAL ख़तरा स्कोर",
      analysis: "विश्लेषण रिपोर्ट", reportHeading: "इस वेबसाइट में क्या समस्या है", finding: "संकेत", findings: "संकेत",
      category: "श्रेणी", severity: "गंभीरता", issue: "नतीजा", penalty: "अंक", noFlags: "कोई चेतावनी संकेत नहीं मिला। कम स्कोर सुरक्षा की गारंटी नहीं है।",
      tlsIssuer: "TLS जारीकर्ता:", certExpires: "प्रमाणपत्र की समय-सीमा", certAge: "प्रमाणपत्र की उम्र",
      pageUnavailable: "पेज जाँच उपलब्ध नहीं:", liveUnavailable: "लाइव जाँच उपलब्ध नहीं:",
      localReply: "मैं पता जाँचने, चेतावनी स्कोर समझने या वैकल्पिक लाइव जाँच इस्तेमाल करने में मदद कर सकता हूँ। मुख्य बॉक्स में वेबसाइट का पता पेस्ट करके पता जाँचें चुनें।",
      disclaimer: "स्वचालित URL जाँच में गलतियाँ हो सकती हैं और यह सुरक्षा की गारंटी नहीं देती।", action: "कार्रवाई:",
      threatIntel: "ख़तरा जानकारी:", urlHeuristics: "URL अनुमान जाँच", aboutOpenPhish: "OpenPhish के बारे में",
      scoreAria: "100 में से ख़तरा स्कोर {score}", formInvalid: "इस पते की जाँच नहीं हो सकी।"
    },
    ta: {
      languageLabel: "மொழி", pageTitle: "ClearSignal — இணையதள பாதுகாப்பு சரிபார்ப்பு", pageDescription: "திறப்பதற்கு முன் ஃபிஷிங் மற்றும் போலி இணையதளக் குறிப்புகளுக்கு முகவரியைச் சரிபார்க்கவும்.", privacy: "உள்ளூரில் தனிப்பட்ட சரிபார்ப்பு", how: "இது எப்படி செயல்படுகிறது",
      eyebrow: "இணைப்பை தெளிவாகச் சரிபார்க்கவும்", headline: "போலியை கண்டறியுங்கள்<br>கிளிக் <span class=\"headline-accent\">செய்வதற்கு முன்.</span>",
      intro: "போலி இணையதளங்கள் யாரையும் ஏமாற்றலாம். திறப்பதற்கு முன், ஃபிஷிங் அறிக்கைகள் மற்றும் சந்தேகக் குறிப்புகளுக்கு முகவரியைச் சரிபார்க்கவும்.",
      chipChecked: "முகவரி சரிபார்க்கப்பட்டது", chipControl: "கட்டுப்பாடு உங்களிடமே",
      checkerTitle: "இணையதள முகவரியைச் சரிபார்க்கவும்", checkerSubtitle: "முகவரி சரிபார்ப்பு தனிப்பட்டது. நேரடி சரிபார்ப்புக்கு உங்கள் அனுமதி தேவை.",
      urlLabel: "இணையதள முகவரி", urlPlaceholder: "இணையதள முகவரியை ஒட்டவும், எ.கா. https://example.com", clear: "முகவரியை அழிக்கவும்", check: "முகவரியைச் சரிபார்க்கவும்", checking: "சரிபார்க்கிறது…",
      hint: "நேரடி ஆய்வு இல்லாமல், URL உள்ளூரிலும் பொது அச்சுறுத்தல் தரவிலும் சரிபார்க்கப்படும்.",
      network: "பொது தளத்தை ஆய்வு செய்யவும் (TLS, வழிமாற்றுகள், DNS, HTML) <span class=\"network-option-note\">(தளத்தைத் தொடர்புகொள்ளும்; அதிகபட்சம் 3 வழிமாற்றுகள்)</span>",
      sectionKicker: "எளிமை. வெளிப்படை. பயனுள்ளது.", sectionTitle: "எது எச்சரிக்கையை ஏற்படுத்தியது என அறியுங்கள்.", sectionIntro: "மர்மமான மதிப்பெண் இல்லை. ஒவ்வொரு சரிபார்ப்புக்கும் தெளிவான விளக்கம் உண்டு.",
      step1Title: "பொது அறிக்கைகளைச் சரிபார்க்கவும்", step1: "புகாரளிக்கப்பட்ட ஃபிஷிங் தளங்களின் OpenPhish பட்டியலுடன் முகவரியை ஒப்பிடுங்கள்.",
      step2Title: "போலி தளங்களைக் கண்டறியுங்கள்", step2: "தொடர்பில்லாத டொமைன்களில் பிராண்ட் பெயர்கள், ஏமாற்றும் முகவரிகள் மற்றும் எச்சரிக்கைக் குறிப்புகளைக் கண்டறியுங்கள்.",
      step3Title: "கட்டுப்பாட்டைத் தக்கவையுங்கள்", step3: "முகவரியைத் திறக்காமலும் இலக்கு தளத்துக்கு தகவல் அனுப்பாமலும் தெளிவான விளக்கத்தைப் பெறுங்கள்.",
      detail1Title: "ஸ்கேன் எதைச் சரிபார்க்கிறது?", detail1: "அறியப்பட்ட ஃபிஷிங் அறிக்கைகள், போலி பிராண்டுகள், ஏமாற்றும் எழுத்துகள், சந்தேகமான URL வடிவங்கள் மற்றும் பிற குறிப்புகளை ஒவ்வொரு ஸ்கேனும் சரிபார்க்கும். எச்சரிக்கைகள் மதிப்பெண்ணுக்குக் கீழே காட்டப்படும்.",
      detail2Title: "நேரடி ஆய்வில் என்ன நடக்கும்?", detail2: "நேரடி ஆய்வு விருப்பமானது; இயல்பாக முடக்கப்பட்டுள்ளது. அனுமதித்தால் TLS சான்றிதழ், வழிமாற்றுகள், DNS, டொமைன் வயது மற்றும் குறைந்த அளவு HTML சரிபார்க்கப்படும். தளத்தின் JavaScript இயக்கப்படாது.",
      detail3Title: "முடிவின் பொருள் என்ன?", detail3: "8-க்குக் குறைவான மதிப்பெண் பாதுகாப்பானது, 8–69 சந்தேகமானது, 70 அல்லது அதற்கு மேல் இந்தப் பயன்பாட்டில் தடுக்கப்படும். இவை ஊகக் குறிப்புகள்; தவறுகள் ஏற்படலாம்.",
      detail4Title: "“தடுக்கப்பட்டது” என்றால் என்ன?", detail4: "அதிக மதிப்பெண் கொண்ட டொமைன்கள் ClearSignal உள்ளூர் தடுப்புப் பட்டியலில் சேர்க்கப்படும். உங்கள் உலாவி, இயக்க முறைமை அல்லது நெட்வொர்க் அமைப்புகள் மாற்றப்படாது. Hosts கோப்பு விதிகள் உங்கள் மதிப்பாய்வுக்காக மட்டுமே பதிவிறக்கப்படும்.",
      reportTitle: "சிக்கல் அல்லது தவறான எச்சரிக்கை உள்ளதா?", reportText: "GitHub-இல் பிழையைப் புகாரளிக்கவும் அல்லது மேம்பாட்டைப் பரிந்துரைக்கவும். பகிர்வதற்கு முன் தனிப்பட்ட URLகள் மற்றும் தகவலை நீக்கவும்.", report: "சிக்கலைப் புகாரளிக்கவும்",
      noteTitle: "இது பயனுள்ள குறிப்பு; உத்தரவாதம் அல்ல.", note: "புதிய அல்லது புகாரளிக்கப்படாத அச்சுறுத்தல்கள் பொது பட்டியல்களில் இருக்காது. சந்தேகம் இருந்தால் சேமித்த புத்தகக்குறி அல்லது அதிகாரப்பூர்வ முகவரியைப் பயன்படுத்துங்கள்.",
      chatToggle: "உதவி வேண்டுமா?", chatTitle: "ClearSignal உதவியாளர்", chatSubtitle: "பயன்பாடு மற்றும் பாதுகாப்பான உலாவல் உதவி",
      chatPrivacy: "செய்திகள் இந்தச் செயலியில் உள்ளூரிலேயே கையாளப்படும்; AI சேவைக்கு அனுப்பப்படாது.",
      chatWelcome: "வணக்கம்! முகவரியைச் சரிபார்க்கவும், ஸ்கேன் முடிவுகளைப் புரிந்துகொள்ளவும், ClearSignal பயன்படுத்தவும் உதவுகிறேன். என்ன உதவி வேண்டும்?",
      suggestion1: "இணையதள முகவரியை எப்படிச் சரிபார்ப்பது?", suggestionLabel1: "இணைப்பை எப்படிச் சரிபார்ப்பது?",
      suggestion2: "மதிப்பெண்ணின் பொருள் என்ன?", suggestionLabel2: "மதிப்பெண் என்ன சொல்கிறது?",
      suggestion3: "நேரடி ஆய்வு என்றால் என்ன?", suggestionLabel3: "நேரடி ஆய்வு என்ன?",
      chatInputLabel: "ClearSignal உதவியாளரிடம் கேளுங்கள்", chatPlaceholder: "கேள்வி கேளுங்கள்…", send: "அனுப்பு", footer: "நம்பிக்கையுடன் உலாவ உதவுகிறோம்.",
      pasteAddress: "தொடங்க இணையதள முகவரியை ஒட்டவும்.", checkerFailed: "சரிபார்ப்பை அடைய முடியவில்லை. மீண்டும் முயற்சிக்கவும்.",
      unavailable: "உதவியாளர் இப்போது கிடைக்கவில்லை. சிறிது நேரம் கழித்து முயற்சிக்கவும்.", checkingAvailability: "உதவியாளர் கிடைப்பதைச் சரிபார்க்கிறது…",
      replying: "உதவியாளர் பதிலளிக்கிறார்…", localAnswered: "ClearSignal உள்ளூர் உதவியாளரின் பதில்.",
      assistantReady: "உதவியாளர் தயார்.", localReady: "உள்ளூர் உதவியாளர் தயார்.",
      chatUnavailable: "உரையாடல் இப்போது கிடைக்கவில்லை.", healthFailed: "உதவியாளர் கிடைப்பதைச் சரிபார்க்க முடியவில்லை.",
      blockedHeading: "தீங்கு விளைவிக்கும் குறிப்புகள் கண்டறியப்பட்டன", suspiciousHeading: "சந்தேகமான குறிப்புகள் கண்டறியப்பட்டன", safeHeading: "வலுவான அச்சுறுத்தல் குறிப்புகள் இல்லை",
      blockedExplain: "வலுவான குறிப்புகள் உள்ளூர் தடுப்பு வரம்பைத் தாண்டின.", suspiciousExplain: "தொடர்வதற்கு முன் முடிவுகளைப் பாருங்கள்.",
      safeExplain: "உயர் நம்பகத்தன்மையுள்ள எச்சரிக்கைகள் இல்லை. இது பாதுகாப்பு உத்தரவாதம் அல்ல.",
      blockedBanner: "இணையதளம் தடுக்கப்பட்டது", blockedInfo: "இந்த டொமைன் ClearSignal உள்ளூர் தடுப்புப் பட்டியலில் சேர்க்கப்பட்டது. உங்கள் சாதனத்தில் மாற்றம் செய்யப்படவில்லை.",
      viewBlocklist: "உள்ளூர் தடுப்புப் பட்டியலைப் பார்க்கவும்", downloadRules: "Hosts விதிகளைப் பதிவிறக்கவும்", score: "CLEARSIGNAL அச்சுறுத்தல் மதிப்பெண்",
      analysis: "ஆய்வு அறிக்கை", reportHeading: "இந்த இணையதளத்தில் என்ன சிக்கல்?", finding: "குறிப்பு", findings: "குறிப்புகள்",
      category: "வகை", severity: "தீவிரம்", issue: "கண்டறிந்தது", penalty: "கழிவு", noFlags: "எச்சரிக்கைக் குறிப்புகள் இல்லை. குறைந்த மதிப்பெண் பாதுகாப்பு உத்தரவாதம் அல்ல.",
      tlsIssuer: "TLS வழங்குநர்:", certExpires: "சான்றிதழ் காலாவதியாகும்", certAge: "சான்றிதழ் வயது",
      pageUnavailable: "பக்க ஆய்வு கிடைக்கவில்லை:", liveUnavailable: "நேரடி சரிபார்ப்பு கிடைக்கவில்லை:",
      localReply: "முகவரியைச் சரிபார்க்கவும், எச்சரிக்கை மதிப்பெண்ணைப் புரிந்துகொள்ளவும் அல்லது விருப்ப நேரடி ஆய்வைப் பயன்படுத்தவும் உதவுகிறேன். முகவரியை முதன்மைப் பெட்டியில் ஒட்டி முகவரியைச் சரிபார்க்கவும் என்பதைத் தேர்ந்தெடுக்கவும்.",
      disclaimer: "தானியங்கி URL சரிபார்ப்பில் தவறுகள் இருக்கலாம்; பாதுகாப்புக்கு உத்தரவாதமில்லை.", action: "செயல்:",
      threatIntel: "அச்சுறுத்தல் தகவல்:", urlHeuristics: "URL மதிப்பீடு", aboutOpenPhish: "OpenPhish பற்றி",
      scoreAria: "100-இல் அச்சுறுத்தல் மதிப்பெண் {score}", formInvalid: "இந்த முகவரியைச் சரிபார்க்க முடியவில்லை."
    }
  };

  const staticText = {
    "h1": "headline",
    ".hero-copy > p": "intro",
    "#checker-title": "checkerTitle", ".checker-heading p": "checkerSubtitle",
    ".sr-only[for='website-url']": "urlLabel", "#website-url": "urlPlaceholder",
    ".clear-input": "clear", ".button-label": "check",
    ".network-option > span": "network", ".section-intro .section-kicker": "sectionKicker",
    ".section-intro h2": "sectionTitle", ".section-intro p": "sectionIntro",
    ".step:nth-child(1) h3": "step1Title", ".step:nth-child(1) p": "step1",
    ".step:nth-child(2) h3": "step2Title", ".step:nth-child(2) p": "step2",
    ".step:nth-child(3) h3": "step3Title", ".step:nth-child(3) p": "step3",
    ".detail-card:nth-child(1) h3": "detail1Title", ".detail-card:nth-child(1) p": "detail1",
    ".detail-card:nth-child(2) h3": "detail2Title", ".detail-card:nth-child(2) p": "detail2",
    ".detail-card:nth-child(3) h3": "detail3Title", ".detail-card:nth-child(3) p": "detail3",
    ".detail-card:nth-child(4) h3": "detail4Title", ".detail-card:nth-child(4) p": "detail4",
    ".report-issue h3": "reportTitle", ".report-issue p": "reportText",
    "#help-chat-title": "chatTitle", ".help-chat-heading p": "chatSubtitle",
    ".help-chat-privacy": "chatPrivacy", ".chat-message.assistant": "chatWelcome",
    ".help-chat-suggestions button:nth-child(1)": "suggestionLabel1",
    ".help-chat-suggestions button:nth-child(2)": "suggestionLabel2",
    ".help-chat-suggestions button:nth-child(3)": "suggestionLabel3",
    ".sr-only[for='help-chat-input']": "chatInputLabel", "#help-chat-input": "chatPlaceholder",
    ".help-chat-send": "send", ".footer-copy": "footer"
  };

  let language = "en";
  const supported = new Set(Object.keys(messages));
  const t = (key, vars = {}) => {
    let value = messages[language]?.[key] || messages.en[key] || key;
    for (const [name, replacement] of Object.entries(vars)) value = value.replace(`{${name}}`, replacement);
    return value;
  };

  function applyLanguage(nextLanguage) {
    language = supported.has(nextLanguage) ? nextLanguage : "en";
    document.documentElement.lang = language;
    document.title = t("pageTitle");
    document.querySelector('meta[name="description"]').content = t("pageDescription");
    try {
      localStorage.setItem("clearsignal-language", language);
    } catch {
      // Language selection still works for the current page if storage is disabled.
    }
    for (const [selector, key] of Object.entries(staticText)) {
      const element = document.querySelector(selector);
      if (!element) continue;
      if (key === "urlPlaceholder" || key === "chatPlaceholder") element.placeholder = t(key);
      else if (key === "clear") element.setAttribute("aria-label", t(key));
      else if (key === "urlLabel" || key === "chatInputLabel") element.textContent = t(key);
      else element.innerHTML = t(key);
    }
    const privacy = document.querySelector(".privacy-note");
    privacy.innerHTML = `<span class="privacy-dot"></span> ${t("privacy")}`;
    const aboutArrow = document.querySelector(".about-link span").outerHTML;
    document.querySelector(".about-link").innerHTML = `${t("how")} ${aboutArrow}`;
    document.querySelector(".eyebrow").innerHTML = `<span class="eyebrow-icon">✳</span> ${t("eyebrow")}`;
    document.querySelector(".chip-top").innerHTML = `<span class="chip-dot"></span> ${t("chipChecked")}`;
    document.querySelector(".chip-bottom").innerHTML = `<span class="chip-check">✓</span> ${t("chipControl")}`;
    const hintIcon = document.querySelector(".form-hint svg").outerHTML;
    document.querySelector(".form-hint").innerHTML = `${hintIcon} ${t("hint")}`;
    const arrow = document.querySelector(".report-issue a span").outerHTML;
    document.querySelector(".report-issue a").innerHTML = `${t("report")} ${arrow}`;
    document.querySelector(".source-note p").innerHTML = `<strong>${t("noteTitle")}</strong> ${t("note")}`;
    document.querySelector("#language-select").value = language;
    document.querySelector("#language-select").setAttribute("aria-label", t("languageLabel"));
    document.querySelector("#help-chat-toggle").innerHTML = `<span aria-hidden="true">?</span> ${t("chatToggle")}`;
    document.querySelector(".help-chat-suggestions button:nth-child(1)").dataset.chatQuestion = t("suggestion1");
    document.querySelector(".help-chat-suggestions button:nth-child(2)").dataset.chatQuestion = t("suggestion2");
    document.querySelector(".help-chat-suggestions button:nth-child(3)").dataset.chatQuestion = t("suggestion3");
    window.dispatchEvent(new CustomEvent("clearsignal-language-change", { detail: { language } }));
  }

  window.clearsignalT = t;
  window.clearsignalLanguage = () => language;
  let initialLanguage = "en";
  try {
    initialLanguage = localStorage.getItem("clearsignal-language") || navigator.language?.slice(0, 2) || "en";
  } catch {
    initialLanguage = navigator.language?.slice(0, 2) || "en";
  }
  document.addEventListener("DOMContentLoaded", () => {
    document.querySelector("#language-select").addEventListener("change", (event) => applyLanguage(event.target.value));
    applyLanguage(initialLanguage);
  });
})();
