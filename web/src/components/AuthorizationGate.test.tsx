import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AuthorizationGate } from "./AuthorizationGate";

// The authorization gate is the safety-critical component: a scan must never
// start without the explicit confirmation. These tests assert it cannot be
// bypassed.
describe("AuthorizationGate", () => {
  it("renders the legal warning with the target", () => {
    render(<AuthorizationGate target="https://example.com" onConfirm={vi.fn()} />);
    expect(screen.getByText(/authorization required/i)).toBeInTheDocument();
    expect(screen.getByText("https://example.com")).toBeInTheDocument();
    expect(screen.getByText(/explicit authorization/i)).toBeInTheDocument();
  });

  it("keeps the launch button disabled until the checkbox is checked", () => {
    render(<AuthorizationGate target="https://example.com" onConfirm={vi.fn()} />);
    const button = screen.getByRole("button", { name: /launch scan/i });
    expect(button).toBeDisabled();
    expect(screen.getByRole("checkbox")).not.toBeChecked();
  });

  it("does NOT call onConfirm when the button is clicked while unchecked", async () => {
    const onConfirm = vi.fn();
    render(<AuthorizationGate target="https://example.com" onConfirm={onConfirm} />);
    // Attempt to force the action without checking the box.
    await userEvent.click(screen.getByRole("button", { name: /launch scan/i }));
    expect(onConfirm).not.toHaveBeenCalled();
  });

  it("enables the button and fires onConfirm only after the box is checked", async () => {
    const onConfirm = vi.fn();
    const user = userEvent.setup();
    render(<AuthorizationGate target="https://example.com" onConfirm={onConfirm} />);

    const button = screen.getByRole("button", { name: /launch scan/i });
    await user.click(screen.getByRole("checkbox"));
    expect(button).toBeEnabled();

    await user.click(button);
    expect(onConfirm).toHaveBeenCalledTimes(1);
  });

  it("re-disables the button when the box is unchecked again", async () => {
    const user = userEvent.setup();
    render(<AuthorizationGate target="https://example.com" onConfirm={vi.fn()} />);
    const button = screen.getByRole("button", { name: /launch scan/i });
    const checkbox = screen.getByRole("checkbox");

    await user.click(checkbox);
    expect(button).toBeEnabled();
    await user.click(checkbox);
    expect(button).toBeDisabled();
  });

  it("disables the button while a scan is submitting even if checked", async () => {
    const user = userEvent.setup();
    render(<AuthorizationGate target="https://example.com" submitting onConfirm={vi.fn()} />);
    await user.click(screen.getByRole("checkbox"));
    expect(screen.getByRole("button", { name: /launching/i })).toBeDisabled();
  });
});
