from .engine import registry, register_class
from .utils import *

# ===== CELL 5: Agents (paste agents.py code) =====

"""
Multi-Agent Security Assessment Agents
"""
import re
import pandas as pd
from abc import abstractmethod

@register_class(alias="Agent.Base")
class Agent:
    """Base agent class"""
    def __init__(self, engine):
        self.engine = engine
        self.system_message = getattr(self, "system_message", "You are an agent.")

    @staticmethod
    def add_parser_args(parser):
        pass

    @abstractmethod
    def speak(self, message, save_to_memory=True):
        pass


# =============================
# PERMISSION EXPERT
# =============================
@register_class(alias="Agent.PermissionExpert.GPT")
class PermissionExpert(Agent):
    """Analyzes dangerous permissions"""
    def __init__(self, args):
        engine = registry.get_class("Engine.GPT")(
            openai_api_key=args.permission_expert_api_key,
            openai_model_name=args.permission_expert_model_name,
            temperature=0.0,
            max_completion_tokens=2048
        )


        self.system_message = (
            "You are a mobile security expert specializing in Android permissions analysis.\n"
            "You can read and understand Arabic app descriptions.\n\n"

            "Your role is to:\n"
            "(1) Analyze the permissions requested by an application\n"
            "(2) Identify dangerous or excessive permissions\n"
            "(3) Assess if permissions align with app functionality (considering Arabic description)\n"
            "(4) Detect permission-functionality mismatches\n"
            "(5) Provide a risk score (0-10) based on permission patterns\n\n"

            "**Arabic App Description Handling:**\n"
            "- If app description is in Arabic, translate key functionality claims\n"
            "- Compare claimed functionality (Arabic) vs. requested permissions\n"
            "- Common Arabic shopping app terms:\n"
            "  • 'تسوق' (shopping), 'منتجات' (products), 'شراء' (buying)\n"
            "  • 'توصيل' (delivery), 'دفع' (payment), 'عروض' (offers)\n"
            "  • Shopping apps DON'T need: camera, microphone, location (unless explicitly delivery-based)\n\n"

            "**Suspicious Permission Patterns:**\n"
            "- Shopping app requesting: READ_SMS, RECORD_AUDIO, CAMERA (without justification)\n"
            "- Excessive permissions for simple functionality\n"
            "- Permissions inconsistent with Arabic description\n\n"

            "**Permission Calibration — Common Safe Permissions:**\n"
            "- These permissions are NORMAL and safe for most apps:\n"
            "  • INTERNET, ACCESS_NETWORK_STATE, ACCESS_WIFI_STATE → standard networking\n"
            "  • WAKE_LOCK → keeps screen on during active use\n"
            "  • READ_EXTERNAL_STORAGE, WRITE_EXTERNAL_STORAGE → saving files/images\n"
            "  • READ_PHONE_STATE → ad SDKs and analytics (very common, not malicious alone)\n"
            "  • VIBRATE → notifications and haptic feedback\n"
            "  • RECEIVE_BOOT_COMPLETED → auto-start (common, not inherently malicious)\n"
            "  • BILLING → in-app purchases (expected in games/shopping apps)\n\n"
            "- These permissions ARE suspicious WITHOUT clear justification:\n"
            "  • READ_SMS, RECEIVE_SMS → no legitimate use in shopping/game apps\n"
            "  • RECORD_AUDIO → only justified in voice/audio/call apps\n"
            "  • READ_CONTACTS → only justified in communication apps\n"
            "  • PROCESS_OUTGOING_CALLS → almost never legitimate\n"
            "  • ACCESS_FINE_LOCATION → only justified if app is explicitly delivery/map-based\n\n"
            "- Do NOT give Risk Score > 5 for apps that only have permissions from the safe list.\n"
            "- Only give Risk Score > 7 when suspicious permissions exist AND\n"
            "  have no justification from the app description.\n"
            "- An app with ONLY safe permissions → Risk Score ≤ 3, Recommendation: Safe.\n\n"

            "**App Category Context — Legitimate High-Permission Apps:**\n"
            "Some app categories LEGITIMATELY require broad permissions by design.\n"
            "Do NOT flag these as Suspicious based on permission count alone:\n\n"
            "- Banking/Financial apps (keywords: bank, pay, token, trade, wallet, finance):\n"
            "  Legitimately need: camera (cheque scan), location (fraud detection),\n"
            "  biometrics, READ_PHONE_STATE, network state — Risk ≤ 4 unless truly anomalous\n\n"
            "- Input Method / Keyboard apps:\n"
            "  Legitimately need: broad system access, READ_CONTACTS (autocomplete),\n"
            "  microphone (voice input) — these are platform requirements, not red flags\n\n"
            "- App Cloners / Multi-account apps:\n"
            "  Legitimately need: almost all permissions to clone other apps\n"
            "  Risk ≤ 4 if app describes cloning/dual functionality\n\n"
            "- Social Media / Video Chat / Live Stream apps:\n"
            "  Legitimately need: camera, microphone, location, contacts, storage\n"
            "  Risk ≤ 4 if permissions match stated social/communication features\n\n"
            "- Call Recorder apps:\n"
            "  Legitimately need: RECORD_AUDIO, READ_CALL_LOG, READ_PHONE_STATE\n"
            "  These are core functionality — not suspicious for this category\n\n"
            "- Enterprise/Business/Telecom apps:\n"
            "  Legitimately need broad permissions for MDM, VPN, connectivity\n"
            "  Risk ≤ 4 unless permissions far exceed stated enterprise functionality\n\n"
            "RULE: For the above categories, only give Risk > 6 if there are permissions\n"
            "that have NO justification even for that category (e.g., banking app with\n"
            "RECORD_AUDIO and no voice feature mentioned).\n\n"

            "\nReturn ONLY the following format (IN ENGLISH):\n\n"
            "#Risk Score#\n"    "(0-10)\n\n"
            "#Confidence#\n"    "(0-100)\n\n"
            "#Evidence#\n"
            "(1) short fact\n"
            "(2) short fact\n"
            "(3) short fact\n\n"
            "#Recommendation#\n"    "(Safe/Suspicious)"

        )
        super(PermissionExpert, self).__init__(engine)
        self.name = "PermissionExpert"

    def analyze_app(self, app_data, app_id):
        """Analyze app permissions with Arabic description awareness"""
        permissions = self.extract_permissions(app_data)
        app_description = app_data.get('description_ar', 'No description')

        is_arabic = contains_arabic(app_description)

        content = (
            f"#App Description {'(Arabic - translate key points)' if is_arabic else ''}#\n"
            f"{app_description}\n\n"
            f"#Requested Permissions ({len(permissions)} total)#\n"
        )

        for i, perm in enumerate(permissions, 1):
            if perm and perm.strip():
                content += f"({i}) {perm}\n"

        if not permissions:
            content += "(No permissions listed - HIGHLY SUSPICIOUS for shopping app)\n"

        messages = [
            {"role": "system", "content": self.system_message},
            {"role": "user", "content": content}
        ]

        response = self.engine.get_response(messages)
        return self.parse_analysis(response)

    def _parse_sections(self, response, keys):
        """Robust parser: handles missing sections, extra whitespace, alternative formats."""
        import re
        result = {}
        if not response:
            return result

        text = response.strip()

        for i, key in enumerate(keys):
            key_pattern = re.escape(key)
            if i < len(keys) - 1:
                next_key_pattern = re.escape(keys[i + 1])
                pattern = rf"#\s*{key_pattern}\s*#\s*(.*?)(?=#\s*{next_key_pattern}\s*#|$)"
            else:
                pattern = rf"#\s*{key_pattern}\s*#\s*(.*?)$"

            match = re.search(pattern, text, re.S | re.I)
            if match:
                value = match.group(1).strip()
                value = re.sub(r'\n*$', '', value).strip()
                if value:
                    result[key] = value

        return result

    def extract_permissions(self, app_data):
        """Extract permissions from JSON app data"""

        permissions = app_data.get("permissions", [])

        # Clean permissions
        cleaned_permissions = [
            str(p).strip()
            for p in permissions
            if p and str(p).strip().lower() not in ['nan', 'none', '']
        ]

        return cleaned_permissions

    def parse_analysis(self, response):
        """Parse structured response (robust version)"""
        keys = [
            "Risk Score",
            "Confidence",
            "Evidence",
            "Recommendation"
        ]
        return self._parse_sections(response, keys)

            # Add to PermissionExpert class
    def reconsider(self, original_analysis, peer_context, app_data, app_id):

      reconsider_prompt = (
          f"You previously analyzed this app. Here is what OTHER SECURITY EXPERTS found:\n\n"
          f"{peer_context}\n\n"
          f"YOUR ORIGINAL ANALYSIS:\n"
          f"Risk Score: {original_analysis.get('Risk Score', 'N/A')}\n"
          f"Recommendation: {original_analysis.get('Recommendation', 'N/A')}\n"
          f"Evidence: {original_analysis.get('Evidence', 'N/A')}\n\n"
          f"TASK:\n"
          f"(1) Review your original analysis against the peer findings.\n"
          f"(2) MAINTAIN your position if peer findings are from a different domain\n"
          f"    and do not affect your specific area of analysis.\n"
          f"(3) UPDATE your position if a peer presents CONCRETE evidence that:\n"
          f"    - Directly relates to your domain, OR\n"
          f"    - Reveals a pattern you did not have full visibility into\n"
          f"(4) Do NOT change based on opinion alone — only on specific factual evidence.\n"
          f"(5) If two or more peers report corroborating suspicious evidence,\n"
          f"    seriously reconsider even if your domain looks clean.\n\n"
          f"BALANCE RULE: Both false positives (calling Safe apps Suspicious) AND\n"
          f"false negatives (missing real threats) are costly. Aim for accuracy, not safety bias.\n\n"
          f"Provide your final analysis in the same output format."
      )


      messages = [
          {"role": "system", "content": self.system_message},
          {"role": "user", "content": reconsider_prompt}
      ]

      response = self.engine.get_response(messages)
      updated = self.parse_analysis(response)

      if not updated:
          return original_analysis

      original_rec = original_analysis.get('Recommendation', '')
      updated_rec = updated.get('Recommendation', '')
      if original_rec != updated_rec:
          print(f"    🔄 {self.name} changed: {original_rec} → {updated_rec}")
      else:
          print(f"    ✅ {self.name} maintained: {updated_rec}")

      return updated



# =============================
# REVIEW EXPERT
# =============================
@register_class(alias="Agent.ReviewExpert.GPT")
class ReviewExpert(Agent):
    """Analyzes Arabic user reviews"""
    def __init__(self, args):
        engine = registry.get_class("Engine.GPT")(
            openai_api_key=args.review_expert_api_key,
            openai_model_name=args.review_expert_model_name,
            temperature=0.0,
            max_completion_tokens=2048
        )

        self.system_message = (
            "You are a mobile security expert specializing in Arabic user review analysis.\n"
            "You are FLUENT in Arabic and understand all dialects (MSA, Egyptian, Gulf, Levantine, Maghrebi).\n\n"

            "Your role is to:\n"
            "(1) Analyze Arabic user reviews for security complaints and fraud indicators\n"
            "(2) Detect Arabic-specific fraud patterns and scam language\n"
            "(3) Identify suspicious review manipulation (fake positive/negative reviews)\n"
            "(4) Understand Arabic sentiment, sarcasm, and cultural context\n"
            "(5) Recognize common Arabic fraud terms and phrases\n"
            "(6) Assess severity of complaints in Arabic context\n"
            "(7) Provide a risk score (0-10) based on Arabic review content\n\n"

            "**IMPORTANT - Arabic Context Awareness:**\n"
            "- Common fraud indicators in Arabic:\n"
            "  • 'نصب' (fraud/scam), 'احتيال' (deception), 'سرقة' (theft)\n"
            "  • 'خداع' (cheating), 'كذب' (lying), 'حرام' (forbidden/wrong)\n"
            "  • 'ضياع فلوس' (money loss), 'ما وصلني شي' (received nothing)\n"
            "  • 'تطبيق وهمي' (fake app), 'ما ينفع' (doesn't work)\n"
            "  • 'سرقوا معلوماتي' (stole my information)\n"
            "  • 'طلع فيروس' (turned out to be virus)\n\n"


            "**CRITICAL — Counterparty fraud vs App fraud:**\n"
                "Many complaints accuse THIRD PARTIES, not the app itself. Distinguish:\n\n"
                "- Marketplace apps (Alibaba, Noon, souq...): 'نصب/احتيال' complaints are\n"
                "  almost always about SELLERS or undelivered orders — this is a\n"
                "  marketplace-quality issue, NOT app malware. Risk <= 4, Safe.\n"
                "- Trading/investment apps: 'نصب' from users who LOST MONEY TRADING is\n"
                "  normal for this category. Only app-level fraud counts: blocked\n"
                "  withdrawals by the operator, unauthorized charges, fake platform.\n"
                "- Dating/chat/live apps: scam complaints about OTHER USERS (fake\n"
                "  profiles, romance scammers) are platform-moderation issues, not\n"
                "  evidence the app is malicious. Risk <= 4 unless the APP itself\n"
                "  charges deceptively or steals data.\n"
                "- Games: 'هكر' nearly always means IN-GAME CHEATERS. 'سرقة' often means\n"
                "  a stolen game account. Neither indicates a malicious app.\n\n"
                "Only recommend Suspicious when complaints describe the APP/DEVELOPER:\n"
                "unauthorized charges, subscription traps, malware behavior ('طلع\n"
                "فيروس'), data theft by the developer ('سرقوا معلوماتي'), fake\n"
                "impersonating app ('تطبيق وهمي'), or operator-blocked withdrawals.\n\n"
                "**Consistency rule:** your Recommendation MUST match your Risk Score:\n"
                "Risk 0-4 → Safe. Risk 7-10 → Suspicious. Risk 5-6 → your judgment.\n\n"

            "Return ONLY the following format (IN ENGLISH):\n\n"

            "#Risk Score#\n"
            "(0-10)\n\n"

            "#Confidence#\n"
            "(0-100)\n\n"

            "#Evidence#\n"
            "(1) short fact (For example, Fraud Indicators)\n"
            "(2) short fact\n"
            "(3) short fact\n\n"

            "#Recommendation#\n"
            "(Safe/Suspicious)"

        )
        super(ReviewExpert, self).__init__(engine)
        self.name = "ReviewExpert"

    def analyze_app(self, app_data, app_id):
      """Analyze app reviews"""

      reviews = self.extract_reviews(app_data)


      if len(reviews) == 0:
          print(f"    ℹ️ ReviewExpert: No Arabic reviews — returning abstain")
          return {
              'Risk Score': '5',
              'Confidence': '15',
              'Evidence': (
                  '(1) No Arabic reviews available — absence of reviews is NOT evidence of safety\n'
                  '(2) Cannot assess user experience or fraud complaints without review data\n'
                  '(3) Insufficient data — defer to PermissionExpert and MetadataExpert findings'
              ),
              'Recommendation': 'Unknown'
          }

      if len(reviews) < 5:
          print(f"    ℹ️ ReviewExpert: Only {len(reviews)} reviews — low confidence")
          # Still call LLM but inject a warning
          low_review_warning = (
              f"\n\nIMPORTANT: Only {len(reviews)} reviews available. "
              f"This is very limited data. Set Confidence ≤ 40 to reflect uncertainty. "
              f"Do NOT give Confidence > 40 with fewer than 5 reviews."
          )
      else:
          low_review_warning = ""


      content = (
          f"#App Name#\n{app_data.get('app_name_ar', 'Unknown')}\n\n"
          f"#Language Note#\n"
          f"Reviews are in Arabic. Analyze carefully considering Arabic linguistic and cultural context.\n\n"
          f"#User Reviews (Arabic - {len(reviews)} reviews)#\n"
      )

      for i, review in enumerate(reviews, 1):
          content += f"({i}) {review}\n"

      if not reviews:
          content += "(No reviews available)\n"

      # ↓↓↓ ADD WARNING TO CONTENT IF FEW REVIEWS ↓↓↓
      content += low_review_warning

      messages = [
          {"role": "system", "content": self.system_message},
          {"role": "user", "content": content}
      ]

      response = self.engine.get_response(messages)
      return self.parse_analysis(response)



    def _parse_sections(self, response, keys):
          """Robust parser: handles missing sections, extra whitespace, alternative formats."""
          import re
          result = {}
          if not response:
              return result

          text = response.strip()

          for i, key in enumerate(keys):
              key_pattern = re.escape(key)
              if i < len(keys) - 1:
                  next_key_pattern = re.escape(keys[i + 1])
                  pattern = rf"#\s*{key_pattern}\s*#\s*(.*?)(?=#\s*{next_key_pattern}\s*#|$)"
              else:
                  pattern = rf"#\s*{key_pattern}\s*#\s*(.*?)$"

              match = re.search(pattern, text, re.S | re.I)
              if match:
                  value = match.group(1).strip()
                  value = re.sub(r'\n*$', '', value).strip()
                  if value:
                      result[key] = value

          return result

    def extract_reviews(self, app_data):
        """Extract reviews from JSON app data"""

        reviews = []

        reviews_data = app_data.get("reviews_ar", [])

        if not isinstance(reviews_data, list):
            return reviews

        for review_obj in reviews_data:

            if not isinstance(review_obj, dict):
                continue

            # Prefer normalized text
            review_text = (
                review_obj.get("text_norm")
                or review_obj.get("text")
                or ""
            )

            review_text = str(review_text).strip()

            if review_text and review_text.lower() not in ['nan', 'none', '']:
                reviews.append(review_text)

        return reviews

    def parse_analysis(self, response):
        """Parse structured response (robust version)"""
        keys = [
            "Risk Score",
            "Confidence",
            "Evidence",
            "Recommendation"
        ]
        return self._parse_sections(response, keys)


    def reconsider(self, original_analysis, peer_context, app_data, app_id):

      reconsider_prompt = (
          f"You previously analyzed this app. Here is what OTHER SECURITY EXPERTS found:\n\n"
          f"{peer_context}\n\n"
          f"YOUR ORIGINAL ANALYSIS:\n"
          f"Risk Score: {original_analysis.get('Risk Score', 'N/A')}\n"
          f"Recommendation: {original_analysis.get('Recommendation', 'N/A')}\n"
          f"Evidence: {original_analysis.get('Evidence', 'N/A')}\n\n"
          f"TASK:\n"
          f"(1) Review your original analysis against the peer findings.\n"
          f"(2) MAINTAIN your position if peer findings are from a different domain\n"
          f"    and do not affect your specific area of analysis.\n"
          f"(3) UPDATE your position if a peer presents CONCRETE evidence that:\n"
          f"    - Directly relates to your domain, OR\n"
          f"    - Reveals a pattern you did not have full visibility into\n"
          f"(4) Do NOT change based on opinion alone — only on specific factual evidence.\n"
          f"(5) If two or more peers report corroborating suspicious evidence,\n"
          f"    seriously reconsider even if your domain looks clean.\n\n"
          f"BALANCE RULE: Both false positives (calling Safe apps Suspicious) AND\n"
          f"false negatives (missing real threats) are costly. Aim for accuracy, not safety bias.\n\n"
          f"Provide your final analysis in the same output format."
      )
      messages = [
          {"role": "system", "content": self.system_message},
          {"role": "user", "content": reconsider_prompt}
      ]

      response = self.engine.get_response(messages)
      updated = self.parse_analysis(response)

      if not updated:
          return original_analysis

      original_rec = original_analysis.get('Recommendation', '')
      updated_rec = updated.get('Recommendation', '')
      if original_rec != updated_rec:
          print(f"    🔄 {self.name} changed: {original_rec} → {updated_rec}")
      else:
          print(f"    ✅ {self.name} maintained: {updated_rec}")

      return updated


# =============================
# METADATA EXPERT
# =============================
@register_class(alias="Agent.MetadataExpert.GPT")
class MetadataExpert(Agent):
    """Analyzes app metadata"""
    def __init__(self, args):
        engine = registry.get_class("Engine.GPT")(
            openai_api_key=args.metadata_expert_api_key,
            openai_model_name=args.metadata_expert_model_name,
            temperature=0.0,
            max_completion_tokens=2048
        )

        self.system_message = (
            "You are a mobile security expert specializing in app metadata analysis.\n\n"
            "Your role is to:\n"
            "(1) Analyze app ratings and rating distributions\n"
            "(2) Detect suspicious rating patterns (rating manipulation)\n"
            "(3) Assess credibility based on number of ratings\n"
            "(4) Identify statistical anomalies\n"
            "(5) Provide a risk score (0-10) based on metadata patterns\n\n"

            "**Calibration — Avoid False Positives:**\n"
            "- Bimodal distributions (high 1★ + high 5★, low middle) are NORMAL for games, utilities, and shopping apps.\n"
            "- At high volume (>1000 ratings), bimodal patterns indicate genuine user diversity, NOT manipulation.\n"
            "- Only flag rating anomalies when:\n"
            "  • >80% five-star ratings with fewer than 500 total reviews\n"
            "  • Complete absence of ALL negative ratings (0 one-star)\n"
            "  • App is less than 3 months old but has >5000 ratings\n"
            "  • Review text contradicts the star ratings (negative text + 5★)\n"
            "- A bimodal/polarized distribution alone at high volume → Risk Score ≤ 4, do NOT recommend Suspicious.\n"


            "Return ONLY the following format (IN ENGLISH):\n\n"

            "#Risk Score#\n"
            "(0-10)\n\n"

            "#Confidence#\n"
            "(0-100)\n\n"

            "#Evidence#\n"
            "(1) short fact \n"
            "(2) short fact\n"
            "(3) short fact\n\n"

            "#Recommendation#\n"
            "(Safe/Suspicious)"



        )
        super(MetadataExpert, self).__init__(engine)
        self.name = "MetadataExpert"


    def analyze_app(self, app_data, app_id):
        """Analyze app metadata"""

        rating = app_data.get("rating_mean", 0)
        total_ratings = app_data.get("rating_count", 0)

        # 1-star to 5-star distribution
        rating_dist = app_data.get("rating_histogram", [])

        content = (
            f"#App Name#\n{app_data.get('app_name_ar', 'Unknown')}\n\n"
            f"#Developer#\n{app_data.get('developer', 'Unknown')}\n\n"
            f"#Overall Rating#\n{rating}\n\n"
            f"#Total Ratings#\n{total_ratings}\n\n"
            f"#Rating Distribution#\n{rating_dist}\n\n"
            "Analyze if the rating pattern shows signs of manipulation or fraud."
        )

        messages = [
            {"role": "system", "content": self.system_message},
            {"role": "user", "content": content}
        ]

        response = self.engine.get_response(messages)

        return self.parse_analysis(response)


    def _parse_sections(self, response, keys):
        """Robust parser: handles missing sections, extra whitespace, alternative formats."""
        import re
        result = {}
        if not response:
            return result

        text = response.strip()

        for i, key in enumerate(keys):
            key_pattern = re.escape(key)
            if i < len(keys) - 1:
                next_key_pattern = re.escape(keys[i + 1])
                pattern = rf"#\s*{key_pattern}\s*#\s*(.*?)(?=#\s*{next_key_pattern}\s*#|$)"
            else:
                pattern = rf"#\s*{key_pattern}\s*#\s*(.*?)$"

            match = re.search(pattern, text, re.S | re.I)
            if match:
                value = match.group(1).strip()
                value = re.sub(r'\n*$', '', value).strip()
                if value:
                    result[key] = value

        return result


    def parse_analysis(self, response):
        keys = [
            "Risk Score",
            "Confidence",
            "Evidence",
            "Recommendation"
        ]
        return self._parse_sections(response, keys)



    # Add to PermissionExpert class
    def reconsider(self, original_analysis, peer_context, app_data, app_id):
        """
        Re-evaluate after seeing what other experts found.
        This enables TRUE agent interaction.
        """
        reconsider_prompt = (
            f"You previously analyzed this app. Here is what OTHER SECURITY EXPERTS found:\n\n"
            f"{peer_context}\n\n"
            f"YOUR ORIGINAL ANALYSIS:\n"
            f"Risk Score: {original_analysis.get('Risk Score', 'N/A')}\n"
            f"Recommendation: {original_analysis.get('Recommendation', 'N/A')}\n"
            f"Evidence: {original_analysis.get('Evidence', 'N/A')}\n\n"
            f"TASK:\n"
            f"(1) Review your original analysis against the peer findings.\n"
            f"(2) MAINTAIN your position if peer findings are from a different domain\n"
            f"    and do not affect your specific area of analysis.\n"
            f"(3) UPDATE your position if a peer presents CONCRETE evidence that:\n"
            f"    - Directly relates to your domain, OR\n"
            f"    - Reveals a pattern you did not have full visibility into\n"
            f"(4) Do NOT change based on opinion alone — only on specific factual evidence.\n"
            f"(5) If two or more peers report corroborating suspicious evidence,\n"
            f"    seriously reconsider even if your domain looks clean.\n\n"
            f"BALANCE RULE: Both false positives (calling Safe apps Suspicious) AND\n"
            f"false negatives (missing real threats) are costly. Aim for accuracy, not safety bias.\n\n"
            f"Provide your final analysis in the same output format."
        )

        messages = [
            {"role": "system", "content": self.system_message},
            {"role": "user", "content": reconsider_prompt}
        ]

        response = self.engine.get_response(messages)
        updated = self.parse_analysis(response)

        # Preserve original if parsing fails
        if not updated:
            return original_analysis

        # Track if position changed
        original_rec = original_analysis.get('Recommendation', '')
        updated_rec = updated.get('Recommendation', '')
        if original_rec != updated_rec:
            print(f"    🔄 {self.name} changed: {original_rec} → {updated_rec}")
        else:
            print(f"    ✅ {self.name} maintained: {updated_rec}")

        return updated


# =============================
# SECURITY JUDGE
# =============================
@register_class(alias="Agent.SecurityJudge.GPT")
class SecurityJudge(Agent):
    """Final decision maker"""
    def __init__(self, args):
        engine = registry.get_class("Engine.GPT")(
            openai_api_key=args.judge_api_key,
            openai_model_name=args.judge_model_name,
            temperature=0.0,
            max_completion_tokens=2048
        )

        self.system_message = (
            "You are a senior Android malware analyst responsible for making the FINAL security decision.\n\n"

            "You do NOT perform a new security analysis.\n"
            "Your job is ONLY to aggregate the findings from three independent experts.\n\n"

            "Each expert provides:\n"
            "- Risk Score (0-10)\n"
            "- Confidence (0-100)\n"
            "- Recommendation (Safe/Suspicious)\n"
            "- Evidence (short factual observations)\n\n"

            "Your responsibilities are:\n"
            "(1) Compare the evidence reported by all experts.\n"
            "(2) Give greater importance to experts with higher confidence.\n"
            "(3) If multiple experts independently report the same issue, treat it as strong evidence.\n"
            "(4) Resolve disagreements using the evidence, NOT long explanations.\n"
            "(5) Produce the final classification.\n\n"

            "IMPORTANT RULES:\n"
            "- Do NOT invent evidence.\n"
            "- Do NOT reinterpret the application yourself.\n"
            "- Base the decision ONLY on the experts' structured outputs.\n"
            "- Evidence is more important than explanations.\n"
            "- Confidence should influence how much you trust an expert.\n\n"

            "Decision Guidelines:\n"
                "- Weight each expert by their reported Confidence.\n"
                "- If two or more active experts recommend Suspicious → classify Suspicious.\n"
                "- If all active experts recommend Safe → classify SAFE. Never contradict a\n"
                "  unanimous verdict; you may only lower your Confidence Score.\n"
                "- If ReviewExpert returns 'Unknown' or Confidence < 30, it is ABSTAINING:\n"
                "  it is neither a Safe nor a Suspicious vote. With an abstaining\n"
                "  ReviewExpert, give MORE weight to PermissionExpert: apps with no reviews\n"
                "  are unvetted, and absence of complaints is NOT evidence of safety.\n"
                "- A single Suspicious expert with Risk >= 6 and Confidence >= 85 is a\n"
                "  meaningful signal — classify Suspicious unless both other experts are\n"
                "  Safe with Confidence >= 90 AND their evidence directly contradicts it.\n"
                "- Permission abuse is a STRONG signal. Fraud complaints in reviews are a\n"
                "  STRONG signal. Rating anomalies alone are a WEAK signal.\n"
                "- False negatives (missing real threats) are exactly as costly as false\n"
                "  positives. Do NOT default to Safe when evidence is mixed — weigh it.\n\n"

            "Output EXACTLY in the following format:\n\n"

            "#Final Classification#\n"
            "(SAFE or Suspicious)\n\n"

            "#Confidence Score#\n"
            "(0-100)\n\n"

            "#Evidences#\n"
            "(1) ...\n"
            "(2) ...\n\n"

            "#Risk Assessment#\n"
            "(Short summary.)"
        )
        super(SecurityJudge, self).__init__(engine)
        self.name = "SecurityJudge"

    def make_decision(self, expert_analyses, app_data, app_id, debate_log=None):
      # Use the JSON structure
      reviews = app_data.get("reviews_ar", []) or []
      desc = app_data.get("description_ar") or app_data.get("description") or ""
      has_arabic_reviews = any(contains_arabic(r.get("text_norm") or r.get("text") or "")
                                for r in reviews if isinstance(r, dict))
      has_arabic_description = contains_arabic(desc)

      content = (
          f"#App Information#\n"
          f"App ID: {app_id}\n"
          f"App Name: {app_data.get('app_name_ar', 'Unknown')}\n"
          f"Language: {'Arabic reviews/description detected' if has_arabic_reviews or has_arabic_description else 'Non-Arabic'}\n\n"
      )

      # ── NEW: Include debate history if any ──
      if debate_log:
          content += "#Debate History#\n"
          content += "The experts had a debate. Here is what changed:\n"
          for log in debate_log:
              content += f"Round {log['round']}:\n"
              if log['changes']:
                  for change in log['changes']:
                      content += f"  - {change}\n"
              else:
                  content += "  - No position changes this round\n"
          content += "\n"

      for expert_name, analysis in expert_analyses.items():

          content += (
              f"\n========================\n"
              f"{expert_name}\n\n"
              f"Risk Score:\n"
              f"{analysis.get('Risk Score', 'N/A')}\n\n"
              f"Confidence:\n"
              f"{analysis.get('Confidence', 'N/A')}\n\n"
              f"Recommendation:\n"
              f"{analysis.get('Recommendation', 'N/A')}\n\n"
              f"Evidence:\n"
              f"{analysis.get('Evidence', 'None')}\n\n"
          )

      content += (
          "\nIMPORTANT:\n"
          "- These are the final expert assessments.\n"
          "- Each expert provides only structured evidence.\n"
          "- Base your decision primarily on the Evidence, Risk Score, and Confidence.\n"
          "- If two experts report the same issue independently, treat it as strong evidence.\n"
          "- Do not invent new evidence.\n"
          "- Resolve disagreements using the strongest evidence.\n"
      )

      messages = [
          {"role": "system", "content": self.system_message},
          {"role": "user", "content": content}
      ]

      response = self.engine.get_response(messages)
      return self.parse_decision(response)

    def _parse_sections(self, response, keys):
        """Robust parser: handles missing sections, extra whitespace, alternative formats."""
        import re
        result = {}
        if not response:
            return result

        text = response.strip()

        for i, key in enumerate(keys):
            key_pattern = re.escape(key)
            if i < len(keys) - 1:
                next_key_pattern = re.escape(keys[i + 1])
                pattern = rf"#\s*{key_pattern}\s*#\s*(.*?)(?=#\s*{next_key_pattern}\s*#|$)"
            else:
                pattern = rf"#\s*{key_pattern}\s*#\s*(.*?)$"

            match = re.search(pattern, text, re.S | re.I)
            if match:
                value = match.group(1).strip()
                value = re.sub(r'\n*$', '', value).strip()
                if value:
                    result[key] = value

        return result


    def parse_decision(self, response):
      keys = [
          "Final Classification",
          "Confidence Score",
          "Evidences",        # ← match the actual header
          "Risk Assessment"
      ]
      return self._parse_sections(response, keys)



