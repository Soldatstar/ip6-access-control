import sys
import subprocess

def main():
    if len(sys.argv) > 1:
        app_name = sys.argv[1]
        try:
            subprocess.run(app_name, check=True)
        except FileNotFoundError:
            print(f"Fehler: Das Programm {app_name} wurde nicht gefunden.")
        except subprocess.CalledProcessError as e:
            print(f"Fehler beim Ausführen von {app_name}: {e}")
    else:
        print("Bitte gib den Namen des auszuführenden Programms als Argument an.")

if __name__ == "__main__":
    main()