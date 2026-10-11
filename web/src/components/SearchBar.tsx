import { useState } from "react";
import type { FormEvent } from "react";
import type { EntityType } from "../types";

interface SearchBarProps {
  onSearch: (query: string, typeOverride?: EntityType) => void;
  disabled: boolean;
}

// "" is auto-detect (the default). The rest force a single type, skipping the
// other types' modules — see the backend's classify_as().
const TYPE_OPTIONS: ReadonlyArray<{ value: "" | EntityType; label: string }> = [
  { value: "", label: "Auto-detect" },
  { value: "person", label: "Person name" },
  { value: "username", label: "Username" },
  { value: "email", label: "Email" },
  { value: "domain", label: "Domain" },
  { value: "ip", label: "IP address" },
  { value: "company", label: "Company" },
];

export function SearchBar({ onSearch, disabled }: SearchBarProps) {
  const [value, setValue] = useState("");
  const [type, setType] = useState<"" | EntityType>("");

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    const trimmed = value.trim();
    if (trimmed) onSearch(trimmed, type || undefined);
  }

  return (
    <form className="search-bar" onSubmit={handleSubmit}>
      <select
        className="search-bar__type"
        value={type}
        onChange={(e) => setType(e.target.value as "" | EntityType)}
        aria-label="Input type"
        title="Force the input type, or let Lantern detect it"
      >
        {TYPE_OPTIONS.map((opt) => (
          <option key={opt.value} value={opt.value}>
            {opt.label}
          </option>
        ))}
      </select>
      <input
        type="text"
        className="search-bar__input"
        placeholder="Name, username, email, domain, IP, or company"
        value={value}
        onChange={(e) => setValue(e.target.value)}
        aria-label="Search query"
        autoFocus
      />
      <button type="submit" className="search-bar__button" disabled={disabled || !value.trim()}>
        {disabled ? "Searching…" : "Search"}
      </button>
    </form>
  );
}
