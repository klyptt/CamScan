# **CAMSCAN - IP Camera Scanner**

-----

## **What it does**

  - **Spots cams fast** - Checks for 60+ camera makes and types.
  - **Grabs proof** - Snaps pics from live feeds.
  - **Cracks weak logins** - Tries 50+ common username/password combos.
  - **Works with all stream types** - Handles HTTP, RTSP, and MJPEG.
  - **Goes easy on networks** - Adapts its speed to prevent slowdowns.

-----

## **Get Started**

### **1. Install stuff**

```bash
pip install requests opencv-python pillow urllib3
```

### **2. Run it**

```bash
# Scan one network
python camfind.py --target 192.168.1.0/24

# Scan specific IPs
python camfind.py --target 192.168.1.10,192.168.1.11

# Max speed scan
python camfind.py --workers 30 --target 10.0.0.0/16
```

### **3. Check the finds** 📂

  - **`found_cameras.txt`** - List of cams found.
  - **`camera_screenshots/`** - Where the pictures go.

-----

## **Why use this?**

I built CamFind because other tools were either blind or too aggressive. This one:

✔ **Actually finds cameras** - Not just random web servers.
✔ **Confirms visually** - No more guessing if it's a real camera.
✔ **Plays nice** - Won't wreck your network.

-----

## **uses**

  - **Security pros** - Find hidden cams in offices.
  - **Home users** - Map all smart cameras at home.
  - **IT admins** - Inventory surveillance gear.

-----

## **Heads up\!** ⚠️

*Use this tool responsibly. Unauthorized scanning is against the law in most places.*

# 🚨 **ILLEGAL EXAMPLE (DO NOT USE)** 🚨

```bash
python camfind.py --target 0.0.0.0/0 
```
# Scans the entire internet (illegal and very irresponsible)

-----

## **The Guts** 

  - **Lightweight** - Few dependencies, runs almost anywhere Python does.
  - **Clear output** - Easy to see what's happening.
  - **Flexible speed** - From careful pokes to full-on sweeps.
