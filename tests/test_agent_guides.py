from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent


def test_agent_guide_documents_repository_ruff_configuration():
    # AGENTS.md delegates commands to the developer guide's local-checks section.
    agents = (REPO_ROOT / "AGENTS.md").read_text(encoding="utf-8")
    guide = (REPO_ROOT / "docs" / "DEVELOPER_GUIDE.md").read_text(encoding="utf-8")

    assert "docs/DEVELOPER_GUIDE.md#running-checks-locally" in agents
    assert "Ruff automatically loads the repository's ruff.toml" in guide
    for text in (agents, guide):
        assert "no config file, defaults" not in text


def test_claude_guide_imports_canonical_agent_guide_without_duplication():
    guide = (REPO_ROOT / "CLAUDE.md").read_text(encoding="utf-8")

    assert "@AGENTS.md" in guide.splitlines()
    assert "## Commands" not in guide
    assert len(guide.splitlines()) <= 8
