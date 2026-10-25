from .engine import registry, register_class
from .agents import *
from .utils import *
from .publishers import *

@register_class(alias="Scenario.AppSecurityAssessment")
class AppSecurityAssessment:
    """Multi-agent app security assessment"""

    @staticmethod
    def add_parser_args(parser):
        parser.add_argument("--app_dataset", type=str, required=True)
        parser.add_argument("--save_path", type=str, default="outputs/results.jsonl")
        parser.add_argument("--num_samples", type=int, default=None)
        parser.add_argument("--permission_expert_api_key", type=str)
        parser.add_argument("--permission_expert_model_name", type=str, default="gpt-4o")
        parser.add_argument("--review_expert_api_key", type=str)
        parser.add_argument("--review_expert_model_name", type=str, default="gpt-4o")
        parser.add_argument("--metadata_expert_api_key", type=str)
        parser.add_argument("--metadata_expert_model_name", type=str, default="gpt-4o")
        parser.add_argument("--judge_api_key", type=str)
        parser.add_argument("--judge_model_name", type=str, default="gpt-4o")

    def __init__(self, args):
        self.args = args
        self.load_dataset()
        self.init_agents()

    def load_dataset(self):
        """Load dataset"""
        import pandas as pd
        import json

        with open(self.args.app_dataset, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.df = pd.DataFrame(data)

        if self.args.num_samples:
            self.df = self.df.head(self.args.num_samples)

        print(f"✅ Loaded {len(self.df)} apps")

    def init_agents(self):
        """Initialize agents"""
        self.permission_expert = registry.get_class("Agent.PermissionExpert.GPT")(self.args)
        self.review_expert = registry.get_class("Agent.ReviewExpert.GPT")(self.args)
        self.metadata_expert = registry.get_class("Agent.MetadataExpert.GPT")(self.args)
        self.security_judge = registry.get_class("Agent.SecurityJudge.GPT")(self.args)
        self.device_expert = registry.get_class("Agent.DeviceRiskExpert.GPT")(self.args)
        print("✅ All agents initialized")

    # ═══════════════════════════════════════════════════════
    # ADD THESE 3 METHODS HERE (BEFORE assess_single_app)
    # ═══════════════════════════════════════════════════════
    def _check_disagreement(self, analyses):
        """Check if experts disagree significantly (robust version)"""
        import re
        recommendations = []
        risk_scores = []


        for name, analysis in analyses.items():
            rec = analysis.get('Recommendation', '').upper()
            if rec == 'UNKNOWN':
                continue  # skip failed experts entirely — don't let them count as an "opinion"
            recommendations.append(rec)

            score_text = str(analysis.get('Risk Score', '0'))
            nums = re.findall(r'\d+\.?\d*', score_text)
            if nums:
                risk_scores.append(float(nums[0]))

        # Trigger debate if experts disagree on recommendation
        if len(set(recommendations)) > 1:
            print(f"  ⚠️ Disagreement detected! Opinions: {recommendations}")
            return True


        # Trigger debate if risk scores differ by 4+ points (raised from 2)
        if risk_scores and (max(risk_scores) - min(risk_scores)) >= 4:
            print(f"  ⚠️ Risk score spread: {min(risk_scores)} to {max(risk_scores)} (range={max(risk_scores) - min(risk_scores)})")
            return True


        return False

    # Tunables — adjust on a DEV split, not the test set
    ABSTAIN_PERM_RISK_THRESHOLD = 4.0   # review abstains + perm risk >= this → Suspicious
    LONE_PERM_RISK = 6.0                # lone PermissionExpert override threshold
    LONE_PERM_CONF = 85.0
    SAFE_UNANIMITY_CONF = 70.0




    def _programmatic_verify(self, expert_analyses, judge_decision, arabic_stats=None):
        """Deterministic decision layer v5. Returns (judge_decision, was_overridden)."""
        ABSTAIN_PERM_RISK = 4.0
        ABSTAIN_PERM_RISK_OBSCURE = 3.0
        OBSCURE_RATING_COUNT = 1000
        MASS_MARKET_RATINGS = 100000
        DEVICE_RISK = 6.0
        DEVICE_CONF = 75.0
        LONE_PERM_RISK = 9.0
        LONE_PERM_CONF = 90.0
        ABSTAIN_CONF = 50.0
        SAFE_UNANIMITY_CONF = 70.0

        import re
        print("  🛡 verify v5 active")

        def get_score(a, f):
            nums = re.findall(r'\d+\.?\d*', str(a.get(f, '0')))
            return float(nums[0]) if nums else 0.0

        def rec_of(a):
            r = a.get('Recommendation', '').strip().lower()
            risk = get_score(a, 'Risk Score')
            if 'suspicious' in r or 'unsafe' in r or 'malicious' in r:
                base = 'suspicious'
            elif 'unknown' in r or not r:
                return 'unknown'
            elif 'safe' in r:
                base = 'safe'
            else:
                return 'unknown'
            if base == 'suspicious' and risk <= 4:
                return 'safe'
            if base == 'safe' and risk >= 7:
                return 'suspicious'
            return base

        perm = expert_analyses.get('PermissionExpert', {})
        rev  = expert_analyses.get('ReviewExpert', {})
        meta = expert_analyses.get('MetadataExpert', {})
        dev  = expert_analyses.get('DeviceRiskExpert', {})

        perm_rec, rev_rec, meta_rec, dev_rec = rec_of(perm), rec_of(rev), rec_of(meta), rec_of(dev)
        perm_risk, rev_risk = get_score(perm, 'Risk Score'), get_score(rev, 'Risk Score')
        meta_risk, dev_risk = get_score(meta, 'Risk Score'), get_score(dev, 'Risk Score')
        perm_conf, rev_conf = get_score(perm, 'Confidence'), get_score(rev, 'Confidence')
        meta_conf, dev_conf = get_score(meta, 'Confidence'), get_score(dev, 'Confidence')

        stats = arabic_stats or {}
        n_ar_reviews = stats.get('arabic_reviews', 0)
        strong_kw = stats.get('strong_fraud_keywords', [])
        strong_kw_reviews = stats.get('strong_keyword_review_count', 0)
        rating_count = stats.get('rating_count', 0)
        package_id = stats.get('package_id', '')

        review_abstaining = (rev_rec == 'unknown') or (rev_conf < ABSTAIN_CONF) \
            or (n_ar_reviews == 0)

        device_active = (dev_rec != 'unknown') and (rating_count < MASS_MARKET_RATINGS)

        votes = {}
        if perm_rec != 'unknown':
            votes['perm'] = perm_rec
        if rev_rec != 'unknown' and not review_abstaining:
            votes['rev'] = rev_rec
        if meta_rec != 'unknown':
            votes['meta'] = meta_rec
        if device_active:
            votes['dev'] = dev_rec

        sus = [k for k, v in votes.items() if v == 'suspicious']
        saf = [k for k, v in votes.items() if v == 'safe']

        strong_double_safe = (perm_rec == 'safe' and meta_rec == 'safe'
                              and perm_conf >= 90 and meta_conf >= 90)

        final, reason, rule = None, None, None

        # R0: known publisher — deterministic accountability.
        #     Only overturnable by 2+ FRAUD experts (perm/rev/meta) at risk >= 7.
        if is_known_publisher(package_id):
            fraud_alarm = sum(1 for r_, k_ in
                              [(perm_rec, perm_risk), (rev_rec, rev_risk),
                              (meta_rec, meta_risk)]
                              if r_ == 'suspicious' and k_ >= 7)
            if fraud_alarm < 2:
                final, rule = 'SAFE', 'R0'
                reason = f"Known publisher ({package_id.split('.')[1]}) — allowlisted"

        # R1: unanimous Suspicious
        if final is None and len(votes) >= 2 and len(sus) == len(votes):
            final, reason, rule = 'Suspicious', 'All active experts Suspicious', 'R1'

        # R2: strong fraud keywords in multiple distinct reviews
        elif final is None and len(strong_kw) >= 2 and n_ar_reviews >= 10 \
                and strong_kw_reviews >= 2:
            final, rule = 'Suspicious', 'R2'
            reason = (f"Strong fraud keywords {strong_kw[:3]} across "
                      f"{strong_kw_reviews} of {n_ar_reviews} Arabic reviews")

        # R3: majority Suspicious
        elif final is None and len(sus) >= 2:
            final, reason, rule = 'Suspicious', f"Majority Suspicious: {sus}", 'R3'

        # R4: lone DeviceRiskExpert — cannot beat double-Safe@90 unless risk >= 8
        elif final is None and device_active and dev_rec == 'suspicious' \
                and dev_risk >= DEVICE_RISK and dev_conf >= DEVICE_CONF \
                and (not strong_double_safe or dev_risk >= 8):
            final, rule = 'Suspicious', 'R4'
            reason = (f"DeviceRiskExpert: sensitive category + obscure developer "
                      f"(Risk {dev_risk}, Conf {dev_conf:.0f}%, volume {rating_count:.0f})")

        # R5: lone ReviewExpert Suspicious
        elif final is None and rev_rec == 'suspicious' and len(sus) == 1:
            if strong_double_safe:
                final, rule = 'SAFE', 'R5'
                reason = (f"Lone ReviewExpert (Risk {rev_risk}) overruled by "
                          f"Perm {perm_conf:.0f}% + Meta {meta_conf:.0f}% Safe")
            elif strong_kw_reviews >= 2 and rev_conf >= 70:
                final, rule = 'Suspicious', 'R5b'
                reason = f"ReviewExpert Suspicious + fraud keywords in {strong_kw_reviews} reviews"
            elif perm_rec == 'safe' and meta_rec == 'safe' and perm_conf >= 80 \
                    and meta_conf >= 80 and rev_risk < 8:
                final, reason, rule = 'SAFE', 'Lone ReviewExpert without corroboration overruled', 'R5c'

        # R6: lone PermissionExpert Suspicious
        elif final is None and perm_rec == 'suspicious' and len(sus) == 1:
            if perm_risk >= LONE_PERM_RISK and perm_conf >= LONE_PERM_CONF:
                final, rule = 'Suspicious', 'R6'
                reason = f"Extreme permission abuse (Risk {perm_risk}, Conf {perm_conf:.0f}%)"
            elif rev_conf >= 80 and meta_conf >= 80:
                final, reason, rule = 'SAFE', \
                    f"Lone PermissionExpert (Risk {perm_risk}) overruled", 'R6b'

        # R7: lone MetadataExpert Suspicious
        elif final is None and meta_rec == 'suspicious' and len(sus) == 1:
            if meta_risk >= 7 and meta_conf >= 85 and n_ar_reviews < 5:
                final, rule = 'Suspicious', 'R7b'
                reason = (f"MetadataExpert Risk {meta_risk} Conf {meta_conf:.0f}% "
                          f"with only {n_ar_reviews} Arabic reviews")
            elif perm_rec == 'safe' and perm_conf >= 80 and rev_conf >= 70:
                final, reason, rule = 'SAFE', 'Lone MetadataExpert (weak signal) overruled', 'R7'

        # R8: no Suspicious votes
        elif final is None and not sus:
            abstain_suspicious = review_abstaining and (
                perm_risk >= ABSTAIN_PERM_RISK
                or (perm_risk >= ABSTAIN_PERM_RISK_OBSCURE
                    and rating_count <= OBSCURE_RATING_COUNT))
            if abstain_suspicious:
                final, rule = 'Suspicious', 'R8'
                reason = (f"ReviewExpert abstaining ({n_ar_reviews} ar-reviews, "
                          f"conf {rev_conf:.0f}) + perm risk {perm_risk} + "
                          f"volume {rating_count:.0f}")
            elif len(saf) == len(votes) and len(votes) >= 2 and \
                    min(perm_conf, meta_conf) >= SAFE_UNANIMITY_CONF:
                final, reason, rule = 'SAFE', 'All active experts Safe', 'R8b'

        if final is not None:
            judge_class = judge_decision.get('Final Classification', '').strip().lower()
            judge_is_sus = 'suspicious' in judge_class
            if judge_is_sus != (final == 'Suspicious') or not judge_class:
                print(f"  🔧 Override [{rule}] → {final} :: {reason}")
                judge_decision['Final Classification'] = final
                judge_decision['Override Rule'] = rule
                judge_decision['Risk Assessment'] = (
                    f"Rule {rule}: {reason}. (Original judge: {judge_class or 'unparsed'})")
                return judge_decision, True
            else:
                judge_decision['Override Rule'] = f"{rule} (agreed with judge)"

        return judge_decision, False



    def _build_shared_context(self, expert_analyses, app_data, app_id):
        """Build summary of all expert findings for sharing"""
        context = f"=== PEER EXPERT FINDINGS (App: {app_data.get('app_name', 'Unknown')}) ===\n\n"
        for expert_name, analysis in expert_analyses.items():
            context += f"--- {expert_name} ---\n"
            for key, value in analysis.items():
                context += f"[{key}]: {value}\n"
            context += "\n"
        return context

    def debate_round(self, expert_analyses, app_data, app_id, round_num=1):
        """Let experts see each other's analysis and revise"""
        print(f"\n🗣️ Debate Round {round_num}...")

        shared_context = self._build_shared_context(expert_analyses, app_data, app_id)

        updated_analyses = {}

        print("  🔐 PermissionExpert reconsidering after seeing peers...")
        updated_analyses['PermissionExpert'] = self.permission_expert.reconsider(
            original_analysis=expert_analyses['PermissionExpert'],
            peer_context=shared_context,
            app_data=app_data,
            app_id=app_id
        )

        print("  💬 ReviewExpert reconsidering after seeing peers...")
        updated_analyses['ReviewExpert'] = self.review_expert.reconsider(
            original_analysis=expert_analyses['ReviewExpert'],
            peer_context=shared_context,
            app_data=app_data,
            app_id=app_id
        )

        print("  📊 MetadataExpert reconsidering after seeing peers...")
        updated_analyses['MetadataExpert'] = self.metadata_expert.reconsider(
            original_analysis=expert_analyses['MetadataExpert'],
            peer_context=shared_context,
            app_data=app_data,
            app_id=app_id
        )

        return updated_analyses

    def _analyze_with_retry(self, expert, app_data, app_id, max_retries=2):
        """Retry expert analysis if it returns empty"""
        for attempt in range(max_retries):
            result = expert.analyze_app(app_data, app_id)

            # Valid result must have at least Recommendation
            if result and result.get('Recommendation'):
                return result

            print(f"  ⚠️ {expert.name} returned empty on attempt {attempt+1}/{max_retries}, retrying...")
# Final fallback — sentinel that gets EXCLUDED from all voting/averaging,
        # not '5' which silently counts as a moderate-risk vote
        print(f"  ❌ {expert.name} failed after {max_retries} attempts — using neutral fallback")
        return {
            'Risk Score': 'N/A',
            'Confidence': '0',
            'Evidence': '(1) Analysis failed — no data available',
            'Recommendation': 'Unknown'
        }


    # ═══════════════════════════════════════════════════════
    # NOW YOUR EXISTING assess_single_app() METHOD
    # ═══════════════════════════════════════════════════════

    def assess_single_app(self, app_data, app_id, debate_rounds=1):
        """Assess single app WITH agent debate"""


        print(f"\n{'='*60}")
        print(f"Assessing App: {app_data.get('app_name_ar', 'Unknown')}")

        arabic_stats = analyze_arabic_text_statistics(app_data)
        print(f"Arabic Content: {arabic_stats['arabic_reviews']}/{arabic_stats['total_reviews']} reviews")
        if arabic_stats['fraud_keywords_found']:
            print(f"⚠️ Fraud keywords: {', '.join(arabic_stats['fraud_keywords_found'][:3])}")
        print(f"{'='*60}")

        # ROUND 0: Independent Analysis
        print("\n📋 ROUND 0: Independent Expert Analysis")
        expert_analyses = {}

        print("\n🔐 Permission Expert (initial)...")
        expert_analyses['PermissionExpert'] = self.permission_expert.analyze_app(app_data, app_id)

        print("💬 Review Expert (initial)...")
        expert_analyses['ReviewExpert'] = self.review_expert.analyze_app(app_data, app_id)

        print("📊 Metadata Expert (initial)...")
        expert_analyses['MetadataExpert'] = self.metadata_expert.analyze_app(app_data, app_id)


        disagreement_detected = self._check_disagreement(expert_analyses)
        debate_log = []

        # Check if any expert has elevated concern
        any_elevated_risk = any(
            float(re.findall(r'\d+\.?\d*', str(a.get('Risk Score', '0')))[0]) >= 5
            for a in expert_analyses.values()
            if re.findall(r'\d+\.?\d*', str(a.get('Risk Score', '0')))
        )

        if disagreement_detected:
            print(f"\n🔥 Disagreement detected — initiating 2 debate rounds!")
            rounds_to_run = 2
        elif any_elevated_risk:
            print(f"\n⚠️ Elevated risk detected — initiating 1 scrutiny round.")
            rounds_to_run = 1  # ← at least review when something looks risky
        else:
            rounds_to_run = 0
            print("\n✅ All experts agree with low risk — skipping debate.")


        for r in range(1, rounds_to_run + 1):
            updated_analyses = self.debate_round(expert_analyses, app_data, app_id, round_num=r)

            round_log = {'round': r, 'changes': []}
            for name in expert_analyses:
                old_rec = expert_analyses[name].get('Recommendation', '')
                new_rec = updated_analyses[name].get('Recommendation', '')
                if old_rec != new_rec:
                    round_log['changes'].append(f"{name}: {old_rec} → {new_rec}")
            debate_log.append(round_log)

            expert_analyses = updated_analyses

            if not self._check_disagreement(expert_analyses):
                print(f"  ✅ Consensus reached after round {r}!")
                break

        print("\n📡 Device/Privacy Expert...")
        expert_analyses['DeviceRiskExpert'] = self._analyze_with_retry(self.device_expert, app_data, app_id)
        print("\n⚖️ Security Judge (with full debate context)...")
        final_decision = self.security_judge.make_decision(
            expert_analyses, app_data, app_id, debate_log=debate_log
        )

        final_decision, was_overridden = self._programmatic_verify(
               expert_analyses, final_decision, arabic_stats=arabic_stats)

        if was_overridden:
            print(f"  ⚠️ Judge decision was overridden by programmatic rules")

        # Robust prediction:
        fc = final_decision.get('Final Classification', '').strip().lower()

        if 'suspicious' in fc or 'malicious' in fc or 'fraud' in fc or 'unsafe' in fc:
            predicted = 1
        elif 'safe' in fc or 'legitimate' in fc or 'benign' in fc:
            predicted = 0
        else:
            # Fallback: weighted vote using both recommendations AND risk scores
            import re as _re
            suspicious_votes = 0
            high_risk_count = 0

            for a in expert_analyses.values():
                rec = a.get('Recommendation', '').lower()
                if 'suspicious' in rec:
                    suspicious_votes += 1

                score_text = str(a.get('Risk Score', '0'))
                nums = _re.findall(r'\d+\.?\d*', score_text)
                if nums and float(nums[0]) >= 6:
                    high_risk_count += 1

            # Suspicious if: 2+ votes OR 2+ high risk scores
            predicted = 1 if (suspicious_votes >= 2 or high_risk_count >= 2) else 0
            print(f"  ⚠️ Judge parse failed — vote={suspicious_votes}/3, high_risk={high_risk_count}/3 → {predicted}")

        result = {
            'app_id': app_id,
            'app_name': app_data.get('app_name_ar', 'Unknown'),
            'ground_truth': app_data.get('label', None),
            'arabic_stats': arabic_stats,
            'expert_analyses': expert_analyses,
            'debate_log': debate_log,
            'disagreement_detected': disagreement_detected,
            'final_decision': final_decision,
            'predicted_label': predicted
        }

        print(f"\n✅ Final: {final_decision.get('Final Classification', 'N/A')}")
        print(f"   Confidence: {final_decision.get('Confidence Score', 'N/A')}")
        if debate_log:
            print(f"   Debate rounds: {len(debate_log)}")

        return result

    def run(self):
        """Run assessment"""
        import jsonlines
        import os

        os.makedirs(os.path.dirname(self.args.save_path), exist_ok=True)
        results = []

        with jsonlines.open(self.args.save_path, mode='w') as writer:
            for idx, row in self.df.iterrows():
                app_data = row.to_dict()
                app_id = app_data.get('app_id', idx)

                try:
                    result = self.assess_single_app(app_data, app_id)
                    writer.write(result)
                    results.append(result)
                except Exception as e:
                    print(f"❌ Error: {e}")
                    continue

        print(f"\n✅ Complete! Saved to: {self.args.save_path}")
        return results



@register_class(alias="Agent.DeviceRiskExpert.GPT")
class DeviceRiskExpert(Agent):
    """Scores data-exposure risk from app category + developer obscurity.
    Complements the fraud-focused experts: this risk is invisible in
    reviews and ratings."""

    def __init__(self, args):
        engine = registry.get_class("Engine.GPT")(
            openai_api_key=(getattr(args, 'device_expert_api_key', None)
                            or args.permission_expert_api_key),
            openai_model_name=(getattr(args, 'device_expert_model_name', None)
                               or args.permission_expert_model_name),
            temperature=0.0,
            max_completion_tokens=2048
        )

        self.system_message = (
            "You are a mobile privacy and supply-chain risk expert.\n"
                "You assess DATA-EXPOSURE risk from the app's category, developer\n"
                "identity, and permissions — NOT from user complaints. Users cannot see\n"
                "data flows, so absence of complaints is NOT evidence of safety.\n"
                "You can read Arabic descriptions.\n\n"

                "STEP 1 — ACCOUNTABILITY CHECK (do this FIRST):\n"
                "An app is ACCOUNTABLE when ANY of these hold:\n"
                "- Globally recognized brand or its subsidiary (Google, Samsung, Huawei,\n"
                "  Xiaomi, Amazon, Alibaba, Baidu, NetEase, AvaTrade, major banks,\n"
                "  telecoms, airlines, retailers)\n"
                "- Developer name clearly matches the app's brand/company and the app is\n"
                "  a business/enterprise tool (attendance, telecom, logistics) — a named\n"
                "  regional company is accountable even if small\n"
                "- Very large user base (>100,000 ratings) with an established identity\n"
                "ACCOUNTABLE apps → Risk <= 3, Safe — regardless of category. STOP here.\n\n"

                "STEP 2 — for NON-accountable apps only:\n\n"

                "HIGH RISK (Risk 7-9, Suspicious) — sensitive data pipeline + obscure\n"
                "developer:\n"
                "- IP/home cameras, baby monitors, video doorbells, DVR/CCTV companions\n"
                "- Health/body devices: smart scales, BP monitors, fitness bands, sleep\n"
                "  trackers, BLE medical/wellness accessories\n"
                "- BLE accessory companions (lights, sensors, gadgets) that also request\n"
                "  location or create cloud accounts\n"
                "- Smart-watch/band sync apps from generic developers\n"
                "- Vehicle apps: OBD diagnostics, car-key programming, telematics,\n"
                "  car-companion apps — especially with meaningless package names\n"
                "  (random letters like zddz.*, single-word generic packages)\n"
                "- TV boxes / casting apps that require a cloud account\n"
                "- Speech/translator/voice apps sending audio to an unknown cloud\n\n"

                "Developer-obscurity indicators (need 2+):\n"
                "- Generic or personal developer name with no company identity\n"
                "- Package name unrelated to any brand, or random-letter packages\n"
                "- Low rating volume (<50,000) for a hardware-companion app\n"
                "- Thin or machine-translated description, no website or privacy info\n\n"

                "LOW RISK (Risk 0-3, Safe):\n"
                "- Anything ACCOUNTABLE (Step 1)\n"
                "- Local-only utilities with NO cloud account: BLE battery readers,\n"
                "  screen-on timers, local display/casting helpers, offline tools\n"
                "- Call recorders storing the USER'S OWN calls locally\n"
                "- VPNs / game accelerators / app cloners / dual-space apps: broad access\n"
                "  is their FUNCTION — judge them by fraud evidence, not category\n"
                "- Games, readers, shopping, social apps from established studios\n\n"

                "MEDIUM (Risk 4-6): sensitive category but partially accountable, or\n"
                "obscure developer with non-sensitive data.\n\n"

                "IMPORTANT:\n"
                "- Judge the DATA PIPELINE, not app quality.\n"
                "- Dating/chat/social: judge only data handling, not user behavior.\n"
                "- Hardware companion + captures video/audio/health/vehicle/location +\n"
                "  obscure developer → Risk >= 7, Suspicious. Do not soften this because\n"
                "  reviews look happy.\n\n"

                "Return ONLY the following format (IN ENGLISH):\n\n"
                "#Risk Score#\n(0-10)\n\n"
                "#Confidence#\n(0-100)\n\n"
                "#Evidence#\n(1) short fact\n(2) short fact\n(3) short fact\n\n"
                "#Recommendation#\n(Safe/Suspicious)"
        )
        super(DeviceRiskExpert, self).__init__(engine)
        self.name = "DeviceRiskExpert"


    def analyze_app(self, app_data, app_id, n_samples=3):
        """Majority-vote over n_samples to suppress run-to-run oscillation."""
        import re as _re

        perms = app_data.get('permissions', []) or []
        perms = [str(p).strip() for p in perms if p and str(p).strip()]
        content = (
            f"#App Name#\n{app_data.get('app_name_ar') or app_data.get('app_name', 'Unknown')}\n\n"
            f"#Package ID#\n{app_id}\n\n"
            f"#Developer#\n{app_data.get('developer', 'Unknown')}\n\n"
            f"#Total Ratings#\n{app_data.get('rating_count', 'Unknown')}\n\n"
            f"#Description (may be Arabic)#\n"
            f"{app_data.get('description_ar') or app_data.get('description', 'None')}\n\n"
            f"#Permissions ({len(perms)})#\n" + "\n".join(perms[:40])
        )
        messages = [
            {"role": "system", "content": self.system_message},
            {"role": "user", "content": content}
        ]

        samples = []
        for _ in range(n_samples):
            try:
                parsed = self.parse_analysis(self.engine.get_response(messages))
                if parsed.get('Recommendation'):
                    samples.append(parsed)
            except Exception as e:
                print(f"    ⚠️ DeviceRiskExpert sample failed: {e}")

        if not samples:
            return {'Risk Score': 'N/A', 'Confidence': '0',
                    'Evidence': '(1) Analysis failed', 'Recommendation': 'Unknown'}

        def _num(a, f):
            nums = _re.findall(r'\d+\.?\d*', str(a.get(f, '0')))
            return float(nums[0]) if nums else 0.0

        sus_samples = [s for s in samples
                      if 'suspicious' in s.get('Recommendation', '').lower()]
        majority_sus = len(sus_samples) * 2 > len(samples)
        winners = sus_samples if majority_sus else \
            [s for s in samples if s not in sus_samples] or samples

        # Median risk/conf across the majority; evidence from its first member
        risks = sorted(_num(s, 'Risk Score') for s in winners)
        confs = sorted(_num(s, 'Confidence') for s in winners)
        result = dict(winners[0])
        result['Risk Score'] = str(risks[len(risks) // 2])
        result['Confidence'] = str(confs[len(confs) // 2])
        result['Recommendation'] = 'Suspicious' if majority_sus else 'Safe'
        result['Votes'] = f"{len(sus_samples)}/{len(samples)} suspicious"
        print(f"    📡 DeviceRiskExpert consensus: {result['Recommendation']} "
              f"({result['Votes']})")
        return result


    def _parse_sections(self, response, keys):
        import re
        result = {}
        if not response:
            return result
        text = response.strip()
        for i, key in enumerate(keys):
            kp = re.escape(key)
            if i < len(keys) - 1:
                nk = re.escape(keys[i + 1])
                pattern = rf"#\s*{kp}\s*#\s*(.*?)(?=#\s*{nk}\s*#|$)"
            else:
                pattern = rf"#\s*{kp}\s*#\s*(.*?)$"
            m = re.search(pattern, text, re.S | re.I)
            if m:
                v = m.group(1).strip()
                if v:
                    result[key] = v
        return result

    def parse_analysis(self, response):
        return self._parse_sections(
            response, ["Risk Score", "Confidence", "Evidence", "Recommendation"])
