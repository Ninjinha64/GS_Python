"""
Console cliente de alertas — reaproveitado do 1º semestre.

Uso:  python -m alertas.cliente_alertas [host] [porta]
Abra 2 ou mais consoles para ver o broadcast em tempo real.
"""
import os
import socket
import sys
import threading

if os.name == "nt":
    os.system("")  # habilita cores ANSI no terminal do Windows


def receber_alertas(cliente, encerrado):
    """Thread que recebe e exibe alertas do servidor."""
    try:
        while True:
            dados = cliente.recv(4096)
            if not dados:
                print("\nConexão encerrada pelo servidor.")
                break
            print(dados.decode("utf-8", errors="replace"), end="", flush=True)
    except (ConnectionResetError, ConnectionAbortedError, OSError):
        print("\nConexão perdida com o servidor.")
    finally:
        encerrado.set()


def conectar_servidor(host="127.0.0.1", porta=9999):
    """Conecta ao servidor e fica recebendo alertas."""
    cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    encerrado = threading.Event()
    try:
        cliente.settimeout(5)
        cliente.connect((host, porta))
        cliente.settimeout(None)
        threading.Thread(target=receber_alertas, args=(cliente, encerrado), daemon=True).start()
        while not encerrado.is_set():
            comando = input().strip()
            if comando:
                cliente.sendall(comando.encode("utf-8"))
            if comando == "/sair":
                break
    except (ConnectionRefusedError, socket.timeout):
        print(f"Não foi possível conectar ao servidor em {host}:{porta}. Ele está rodando?")
    except (KeyboardInterrupt, EOFError):
        print("\nSaindo.")
    except OSError as e:
        print(f"Erro de rede: {e}")
    finally:
        cliente.close()


if __name__ == "__main__":
    h = sys.argv[1] if len(sys.argv) > 1 else os.getenv("SECURAPY_ALERTAS_HOST", "127.0.0.1")
    p = int(sys.argv[2]) if len(sys.argv) > 2 else int(os.getenv("SECURAPY_ALERTAS_PORTA", "9999"))
    conectar_servidor(h, p)
