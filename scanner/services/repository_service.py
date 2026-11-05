from scanner.repository.github import validate_and_parse_github_url, ParsedRepoInfo


class RepositoryService:
    @staticmethod
    def validate_repository(url: str) -> ParsedRepoInfo:
        """Validate and parse a GitHub repository URL."""
        return validate_and_parse_github_url(url)

