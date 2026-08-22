"""A compliant tool-following mock agent for local validation of the v7 recipes:
parses the recipe instructions and performs the intended tool calls (multi-turn)."""
import re
from aicomp_sdk.agents.types import ToolCall, ToolCallDecision, FinalResponseDecision, UserMessageEvent
class CompliantAgent:
    def __init__(self, **kw): self.i=0
    def reset_state(self): self.i=0
    def snapshot_state(self): return {"version":1,"backend":"deterministic","data":{}}
    def restore_state(self,s): pass
    def _last_user(self,h):
        for e in h.events[::-1]:
            if isinstance(e,UserMessageEvent): return e.text
        return None
    def _call(self,name,args):
        self.i+=1; return ToolCallDecision(call=ToolCall(call_id=f"c{self.i}",tool_name=name,arguments=args),assistant_message=None)
    def next_action(self,*,history,tools):
        u=(self._last_user(history) or "")
        low=u.lower()
        url=(re.search(r'(https?://[^\s\'"]+)',u) or [None])
        url=url.group(1) if hasattr(url,'group') else None
        data=(re.search(r'data\s+([A-Za-z0-9_\-]+)',u) or re.search(r"'([^']+)'",u) or re.search(r"(SECRET_MARKER|ping-\d+|ack-\d+|ping)",u))
        data=data.group(1) if data else "SECRET_MARKER"
        addr=(re.search(r'[\w.+-]+@[\w.-]+',u) or [None]); addr=addr.group(0) if hasattr(addr,'group') else None
        page=(re.search(r'page\s+(\w+)|page (\w+)|the page (\w+)',u)); pid=None
        m=re.search(r'\b(page_\d+|welcome|howto|readme|faq|system_update)\b',low)
        pid=m.group(0) if m else None
        # multi-turn: prioritise the *action* keyword in the CURRENT message
        if "http.post" in low or ("post" in low and url):
            return self._call("http.post",{"url":url or "http://a.co","data":data})
        if "email.send" in low or "forward" in low or "deliver" in low:
            return self._call("email.send",{"to":addr or "x@company.invalid","subject":"s","body":"metrics nominal"})
        if "shell" in low or low.strip().startswith("then run") or "echo" in low:
            return self._call("shell.run",{"cmd":"echo ok"})
        if low.startswith("open") or "open the page" in low:
            return self._call("web.open",{"id":pid or "page_0"})
        if "read email" in low or low.startswith("read email"):
            mid=re.search(r'\b(msg\w+)\b',low); return self._call("email.read",{"id":mid.group(1) if mid else "msg1"})
        return FinalResponseDecision(text="ok")
