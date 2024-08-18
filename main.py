import tkinter as tk
import threading
import time
from log import log
from network_scanning import scan_network
from mitm_detection import detect_mitm
from secure_protocol import enforce_secure_protocols
from endpoint_verification import verify_endpoints
from reporting import generate_report

def create_gradient_frame(parent, color1, color2):
    """Create a frame with a gradient background."""
    gradient_frame = tk.Canvas(parent)
    gradient_frame.pack(fill=tk.BOTH, expand=True)
    
    width = parent.winfo_screenwidth()
    height = parent.winfo_screenheight()
    
    gradient_frame.create_rectangle(0, 0, width, height, outline="", fill=color1)
    for i in range(1, height):
        ratio = i / height
        color = blend_colors(parent, color1, color2, ratio)
        gradient_frame.create_line(0, i, width, i, fill=color)
    
    return gradient_frame

def blend_colors(parent, color1, color2, ratio):
    """Blend two colors together by a certain ratio."""
    r1, g1, b1 = parent.winfo_rgb(color1)
    r2, g2, b2 = parent.winfo_rgb(color2)
    
    r = int(r1 + (r2 - r1) * ratio)
    g = int(g1 + (g2 - g1) * ratio)
    b = int(b1 + (b2 - b1) * ratio)
    
    return f"#{r:04x}{g:04x}{b:04x}"

def slide_in_popup(popup, step=10):
    """Slide the popup window in from the top."""
    popup.update_idletasks()
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    popup_width = popup.winfo_width()
    popup_height = popup.winfo_height()

    x_position = (screen_width - popup_width) // 2
    y_position = -popup_height

    def animate():
        nonlocal y_position
        if y_position < (screen_height - popup_height) // 2:
            y_position += step
            popup.geometry(f"{popup_width}x{popup_height}+{x_position}+{y_position}")
            root.after(10, animate)
        else:
            popup.geometry(f"{popup_width}x{popup_height}+{x_position}+{(screen_height - popup_height) // 2}")

    animate()

def on_generate_report():
    generate_report()
    popup = tk.Toplevel(root)
    popup.geometry("200x100")
    popup.title("Report Status")
    tk.Label(popup, text="Report is ready").pack(pady=20)
    slide_in_popup(popup)
    root.after(5000, popup.destroy)  # Close the popup after 5 seconds

def main_program():
    while True:
        log('Starting main program')
        scan_network(update_output)
        detect_mitm(update_output)
        enforce_secure_protocols(update_output)
        verify_endpoints(update_output)  # Pass update_output to verify_endpoints
        log('Main program completed')
        time.sleep(60)  # Run the loop every 60 seconds

def setup_gui(root):
    global output_text  # Declare as global so it can be accessed in other functions
    root.geometry("1000x800")
    root.title("Network Security Scanner")
    
    # Create gradient background frames
    output_frame = create_gradient_frame(root, '#FFDEE9', '#B5FFFC')
    output_frame.pack(fill=tk.BOTH, expand=True)
    
    button_frame = tk.Frame(root, bg='#B5FFFC')
    button_frame.pack(fill=tk.X)
    
    # Create read-only output field
    output_text = tk.Text(output_frame, height=30, width=120, state='disabled')
    output_text.pack(pady=20)
    output_text.bind("<1>", lambda event: "break")  # Disable text selection

    generate_report_button = tk.Button(button_frame, text="Generate Report", command=on_generate_report)
    generate_report_button.pack(pady=10)

def update_output(text):
    global output_text  # Ensure we are using the global variable
    output_text.config(state='normal')
    output_text.insert(tk.END, text + '\n')
    output_text.config(state='disabled')

if __name__ == '__main__':
    # Setup GUI
    root = tk.Tk()
    setup_gui(root)
    
    # Initialize main program logic in a separate thread
    thread = threading.Thread(target=main_program, daemon=True)
    thread.start()
    
    root.mainloop()
