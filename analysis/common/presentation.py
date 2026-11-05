"""Reusable terminal help formatting and native PNG display."""

import argparse


class SingleLineHelpFormatter(argparse.HelpFormatter):
    """Keep option descriptions on the same line, regardless of terminal width."""

    def __init__(self, prog):
        super().__init__(prog, max_help_position=48, width=1000)

    def _split_lines(self, text, width):
        return [" ".join(text.split())]


def preflight(output, cmap):
    import matplotlib

    if cmap not in matplotlib.colormaps:
        raise ValueError(f"Unknown colormap: {cmap}")
    if output:
        matplotlib.use("Agg")
        return
    try:
        matplotlib.use("TkAgg", force=True)
        import matplotlib.pyplot as plt

        fig = plt.figure()
        plt.close(fig)
    except Exception as error:
        raise RuntimeError(
            "Could not open a graphical window. Use --out path.png or run with Tk and access to a graphical session."
        ) from error


def show_png(path):
    import matplotlib.pyplot as plt

    img = plt.imread(path)
    fig, ax = plt.subplots(figsize=(10, 7))
    fig.canvas.manager.set_window_title(path.name)
    ax.imshow(img)
    ax.axis("off")
    fig.tight_layout(pad=0)
    plt.show()
