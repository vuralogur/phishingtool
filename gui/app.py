"""CustomTkinter desktop front-end for the phishing detector.

Thin layer over detector.analyzer — the engine is unchanged. Analysis runs in a
worker thread so the window never freezes (especially in --online mode).
"""
from __future__ import annotations
import threading
from pathlib import Path
from tkinter import filedialog, messagebox

import customtkinter as ctk

from detector import analyzer, report

SEV_COLORS = {
    "low": "#2fa84f",
    "medium": "#e0a800",
    "high": "#e8590c",
    "critical": "#d6336c",
}
VERDICT_EMOJI = {"low": "🟢", "medium": "🟡", "high": "🟠", "critical": "🔴"}
_IDLE = "#3a3a3a"
_BUSY = "#444444"

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Phishing Tespit")
        self.geometry("920x700")
        self.minsize(720, 560)
        self._ctx = analyzer.build_context()
        self._last_result = None
        self._last_source = None
        self._build()

    # ---------- layout ----------
    def _build(self):
        top = ctk.CTkFrame(self)
        top.pack(fill="x", padx=12, pady=(12, 6))
        ctk.CTkButton(top, text="Dosya Seç (.eml/.msg)", command=self._pick_file).pack(
            side="left", padx=6, pady=8)
        self.online_var = ctk.BooleanVar(value=False)
        ctk.CTkSwitch(top, text="Online (DNS/WHOIS/itibar)", variable=self.online_var).pack(
            side="left", padx=12)
        self.save_btn = ctk.CTkButton(top, text="JSON Kaydet", command=self._save_json,
                                      state="disabled", width=120)
        self.save_btn.pack(side="right", padx=6, pady=8)

        paste = ctk.CTkFrame(self)
        paste.pack(fill="x", padx=12, pady=6)
        ctk.CTkLabel(paste, text="veya ham e-postayı buraya yapıştır:").pack(
            anchor="w", padx=8, pady=(6, 0))
        self.textbox = ctk.CTkTextbox(paste, height=90)
        self.textbox.pack(fill="x", padx=8, pady=6)
        ctk.CTkButton(paste, text="Metni Analiz Et", command=self._analyze_text).pack(
            anchor="e", padx=8, pady=(0, 8))

        self.badge = ctk.CTkLabel(
            self, text="Analiz bekleniyor…", height=58, corner_radius=10,
            fg_color=_IDLE, font=ctk.CTkFont(size=22, weight="bold"))
        self.badge.pack(fill="x", padx=12, pady=6)

        self.auth_label = ctk.CTkLabel(self, text="", font=ctk.CTkFont(size=13),
                                       anchor="w", justify="left")
        self.auth_label.pack(fill="x", padx=16)

        self.list_frame = ctk.CTkScrollableFrame(self, label_text="Göstergeler")
        self.list_frame.pack(fill="both", expand=True, padx=12, pady=(6, 12))

    # ---------- actions ----------
    def _pick_file(self):
        path = filedialog.askopenfilename(
            title="E-posta seç",
            filetypes=[("E-posta (.eml/.msg)", "*.eml *.msg"),
                       ("Tüm dosyalar", "*.*")])
        if path:
            self._run(lambda: analyzer.analyze_file(
                path, online=self.online_var.get(), ctx=self._ctx), source=path)

    def _analyze_text(self):
        text = self.textbox.get("1.0", "end").strip()
        if not text:
            messagebox.showinfo("Bilgi", "Önce ham e-posta metnini yapıştırın.")
            return
        self._run(lambda: analyzer.analyze_text(
            text, online=self.online_var.get(), ctx=self._ctx),
            source="(yapıştırılan metin)")

    def _run(self, fn, source):
        self.badge.configure(text="Analiz ediliyor…", fg_color=_BUSY)
        self.save_btn.configure(state="disabled")

        def worker():
            try:
                res = fn()
            except Exception as exc:  # parse / analysis error
                self.after(0, lambda: self._error(str(exc)))
                return
            self.after(0, lambda: self._render(res, source))

        threading.Thread(target=worker, daemon=True).start()

    # ---------- rendering ----------
    def _clear_list(self):
        for w in self.list_frame.winfo_children():
            w.destroy()

    def _error(self, msg):
        self.badge.configure(text="HATA", fg_color=SEV_COLORS["critical"])
        self.auth_label.configure(text=msg)
        self._clear_list()

    def _render(self, result, source):
        self._last_result = result
        self._last_source = source
        color = SEV_COLORS.get(result.verdict, _IDLE)
        emoji = VERDICT_EMOJI.get(result.verdict, "")
        self.badge.configure(
            text=emoji + "  " + result.verdict.upper() + "   —   skor "
                 + str(result.score) + "/" + str(result.max_score),
            fg_color=color)
        a = result.auth
        head = ("Kaynak: " + source + "     |     SPF=" + a["spf"]
                + "   DKIM=" + a["dkim"] + "   DMARC=" + a["dmarc"])
        # Compact ATT&CK line here (ids only); each card carries its own id.
        attck = report.technique_summary_line(result)
        self.auth_label.configure(
            text="\n".join([head] + report.breakdown_lines(result) +
                           ([attck] if attck else [])))
        self.save_btn.configure(state="normal")
        self._clear_list()
        if not result.indicators:
            ctk.CTkLabel(self.list_frame,
                         text="Gösterge yok — belirgin phishing işareti bulunamadı.",
                         text_color=SEV_COLORS["low"]).pack(anchor="w", padx=8, pady=8)
            return
        for ind in result.indicators:
            self._card(ind)

    def _card(self, ind):
        c = SEV_COLORS.get(ind.severity, "#666666")
        card = ctk.CTkFrame(self.list_frame, fg_color="#2b2b2b", corner_radius=8)
        card.pack(fill="x", padx=6, pady=4)
        stripe = ctk.CTkFrame(card, fg_color=c, width=6, corner_radius=8)
        stripe.pack(side="left", fill="y", padx=(0, 8), pady=2)
        body = ctk.CTkFrame(card, fg_color="transparent")
        body.pack(side="left", fill="x", expand=True, pady=6)
        ctk.CTkLabel(
            body,
            text="[" + ind.severity.upper() + "]  +" + str(ind.weight) + "   "
                 + ind.id + "  (" + ind.category + ")"
                 + ("   ·   " + ind.technique if ind.technique else ""),
            font=ctk.CTkFont(size=13, weight="bold"), text_color=c,
            anchor="w", justify="left").pack(fill="x", padx=4)
        ctk.CTkLabel(body, text="kanıt: " + ind.evidence, anchor="w",
                     justify="left", wraplength=780).pack(fill="x", padx=4)
        ctk.CTkLabel(body, text=ind.explanation, anchor="w", justify="left",
                     wraplength=780, text_color="#9a9a9a").pack(fill="x", padx=4)

    def _save_json(self):
        if not self._last_result:
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("Tüm dosyalar", "*.*")])
        if path:
            Path(path).write_text(
                report.to_json(self._last_result, source=self._last_source),
                encoding="utf-8")
            messagebox.showinfo("Kaydedildi", path)


def main():
    App().mainloop()


if __name__ == "__main__":
    main()
