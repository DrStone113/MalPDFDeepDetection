from __future__ import annotations

import inspect
import os
from pathlib import Path
import sys
import tempfile

PROD_ROOT = Path(__file__).resolve().parent
REPO_ROOT = PROD_ROOT.parent
for candidate_src in (PROD_ROOT / "src", REPO_ROOT / "src"):
    if candidate_src.is_dir() and str(candidate_src) not in sys.path:
        sys.path.insert(0, str(candidate_src))
if str(PROD_ROOT) not in sys.path:
    sys.path.insert(0, str(PROD_ROOT))

os.environ["GRADIO_SSR_MODE"] = "false"
os.environ.setdefault(
    "MALPDF_QUARANTINE_DIR",
    str(Path(tempfile.gettempdir()) / "malpdf_quarantine"),
)


class _LocalSpacesShim:
    @staticmethod
    def GPU(fn=None, **_kwargs):
        if fn is None:
            return lambda target: target
        return fn


try:
    import spaces
except ImportError:
    spaces = _LocalSpacesShim()

try:
    import gradio as gr
except ImportError:
    gr = None


@spaces.GPU
def zerogpu_accelerator_check(ping: str = "status") -> str:
    try:
        import torch

        accel = torch.cuda.get_device_name(0) if torch.cuda.is_available() else "cpu"
    except Exception:
        accel = "onnxruntime-cpu"
    return f"MalPDF DeepDetection ONNX Runtime sẵn sàng ({ping}) | Thiết bị: {accel}"


demo = None
if gr is not None:
    with gr.Blocks(title="MalPDF DeepDetection") as demo:
        gr.HTML(
            '<div style="padding:16px;font-family:system-ui,sans-serif;">'
            '<h3>MalPDF DeepDetection (ONNX Runtime Production)</h3>'
            '<p>Mở giao diện kiểm tra PDF đầy đủ tại <a href="/ui">/ui</a>.</p>'
            "</div>"
        )
        probe_in = gr.Textbox(value="health", label="Tham số kiểm tra")
        probe_out = gr.Textbox(label="Trạng thái thực thi")
        probe_btn = gr.Button("Kiểm tra phần cứng")
        probe_btn.click(fn=zerogpu_accelerator_check, inputs=[probe_in], outputs=[probe_out])


def run_production_server() -> None:
    port = int(os.environ.get("GRADIO_SERVER_PORT", os.environ.get("PORT", "7860")))
    if gr is not None and demo is not None:
        from web_service import production_router

        launch_params = inspect.signature(demo.launch).parameters
        launch_kwargs: dict[str, object] = {
            "server_name": "0.0.0.0",
            "server_port": port,
            "prevent_thread_lock": True,
        }
        if "ssr_mode" in launch_params:
            launch_kwargs["ssr_mode"] = False
        if "show_error" in launch_params:
            launch_kwargs["show_error"] = True

        launch_result = demo.launch(**launch_kwargs)
        gradio_app = getattr(demo, "server_app", None)
        if gradio_app is None and isinstance(launch_result, tuple) and len(launch_result) > 0:
            gradio_app = launch_result[0]
        if gradio_app is None:
            raise RuntimeError("gradio_server_app_unavailable")

        gradio_app.router.routes[0:0] = list(production_router.routes)
        demo.block_thread()
    else:
        import uvicorn
        from web_service import app as standalone_app

        uvicorn.run(standalone_app, host="0.0.0.0", port=port)


if __name__ == "__main__":
    run_production_server()

