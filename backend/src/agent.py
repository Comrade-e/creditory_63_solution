"""Агент рекомендаций кредитных продуктов на smolagents + Hugging Face."""

from __future__ import annotations

import json
import os
import re
from typing import Any
from uuid import UUID

from smolagents import InferenceClientModel, Tool, ToolCallingAgent

try:
    from backend.src.db import get_connection
except ImportError:
    from db import get_connection


class RecommendationApplicationNotFound(Exception):
    """Заявка не найдена или недоступна текущему пользователю."""


class RecommendationGenerationError(Exception):
    """Ошибка вызова LLM или обработки результата."""


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _find_number(
    objects: list[dict[str, Any]],
    possible_keys: set[str],
) -> float | None:
    """Ищет сумму или срок в JSONB с camelCase/snake_case ключами."""

    def walk(value: Any) -> float | None:
        if isinstance(value, dict):
            for key, child in value.items():
                normalized = re.sub(
                    r"[^a-z0-9]", "", str(key).lower()
                )
                if normalized in possible_keys and child is not None:
                    try:
                        return float(child)
                    except (TypeError, ValueError):
                        pass

                found = walk(child)
                if found is not None:
                    return found

        elif isinstance(value, list):
            for child in value:
                found = walk(child)
                if found is not None:
                    return found

        return None

    for obj in objects:
        found = walk(obj)
        if found is not None:
            return found

    return None


def _parse_json_result(raw: Any) -> dict[str, Any]:
    """Извлекает JSON-объект из ответа модели."""

    if isinstance(raw, dict):
        parsed = raw
    else:
        text = str(raw).strip()
        text = re.sub(
            r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE
        )
        text = re.sub(r"\s*```$", "", text)

        start = text.find("{")
        end = text.rfind("}")

        if start < 0 or end <= start:
            raise RecommendationGenerationError(
                "Модель не вернула JSON-объект"
            )

        try:
            parsed = json.loads(text[start : end + 1])
        except json.JSONDecodeError as exc:
            raise RecommendationGenerationError(
                "Модель вернула некорректный JSON"
            ) from exc

    if not isinstance(parsed, dict):
        raise RecommendationGenerationError(
            "Ответ модели должен быть JSON-объектом"
        )

    return parsed


class LoadRecommendationContextTool(Tool):
    """Загружает заявку и активные продукты из PostgreSQL."""

    name = "load_recommendation_context"

    description = (
        "Загружает данные заявки и активные кредитные продукты. "
        "Обязательно вызови инструмент перед составлением рекомендаций. "
        "Можно получить только заявку текущего авторизованного пользователя."
    )

    inputs = {
        "application_id": {
            "type": "string",
            "description": "UUID заявки для анализа",
        }
    }

    output_type = "string"

    def __init__(self, user_id: UUID | str):
        super().__init__()
        # user_id передаётся бэкендом после проверки авторизации.
        # Модель не может изменить его через аргументы инструмента.
        self._authenticated_user_id = str(user_id)
        self.context: dict[str, Any] | None = None
        self.application_not_found = False

    def forward(self, application_id: str) -> str:
        """Возвращает контекст заявки в JSON."""

        try:
            application_uuid = UUID(application_id)
        except (TypeError, ValueError, AttributeError):
            return json.dumps(
                {"error": "invalid_application_id"},
                ensure_ascii=False,
            )

        with get_connection() as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    id,
                    company_data,
                    selected_product_id,
                    original_terms,
                    active_terms,
                    status
                FROM applications
                WHERE id = %s AND user_id = %s
                """,
                (
                    application_uuid,
                    self._authenticated_user_id,
                ),
            )

            row = cur.fetchone()

            if row is None:
                self.application_not_found = True
                return json.dumps(
                    {"error": "application_not_found"},
                    ensure_ascii=False,
                )

            cur.execute(
                """
                SELECT
                    id,
                    name,
                    purpose,
                    description,
                    min_amount,
                    max_amount,
                    min_term_months,
                    max_term_months,
                    annual_rate
                FROM loan_products
                WHERE is_active IS TRUE
                ORDER BY name
                """
            )

            product_rows = cur.fetchall()

        company_data = _as_dict(row[1])
        original_terms = _as_dict(row[3])
        active_terms = _as_dict(row[4])

        products = []

        for product in product_rows:
            products.append({
                "id": str(product[0]),
                "name": product[1],
                "purpose": product[2],
                "description": product[3] or "",
                "minAmount": (
                    float(product[4])
                    if product[4] is not None else None
                ),
                "maxAmount": (
                    float(product[5])
                    if product[5] is not None else None
                ),
                "minTermMonths": (
                    int(product[6])
                    if product[6] is not None else None
                ),
                "maxTermMonths": (
                    int(product[7])
                    if product[7] is not None else None
                ),
                "annualRate": (
                    float(product[8])
                    if product[8] is not None else None
                ),
            })

        # Не передаём модели все поля компании без необходимости.
        allowed_company_keys = {
            "companyname",
            "industry",
            "okved",
            "companytype",
            "businessactivity",
            "businessdescription",
            "companysize",
            "revenue",
            "employeecount",
        }

        filtered_company_data = {
            key: value
            for key, value in company_data.items()
            if re.sub(
                r"[^a-z0-9]", "", str(key).lower()
            ) in allowed_company_keys
        }

        self.context = {
            "applicationId": str(row[0]),
            "companyData": filtered_company_data,
            "originalTerms": original_terms,
            "activeTerms": active_terms,
            "selectedProductId": (
                str(row[2]) if row[2] else None
            ),
            "status": row[5],
            "activeProducts": products,
        }

        return json.dumps(
            self.context,
            ensure_ascii=False,
            default=str,
        )


def _make_agent(
    context_tool: LoadRecommendationContextTool,
) -> ToolCallingAgent:
    token = os.getenv("HF_TOKEN")

    if not token:
        raise RecommendationGenerationError(
            "Не настроена переменная окружения HF_TOKEN"
        )

    model = InferenceClientModel(
        model_id=os.getenv(
            "HF_MODEL_ID",
            "Qwen/Qwen3-Next-80B-A3B-Thinking",
        ),
        provider=os.getenv("HF_PROVIDER") or None,
        token=token,
        temperature=0.1,
        max_tokens=1800,
        timeout=90,
    )

    return ToolCallingAgent(
        tools=[context_tool],
        model=model,
        max_steps=3,
        verbosity_level=0,
        instructions=(
            "Ты агент рекомендаций кредитных продуктов для бизнеса. "
            "Сначала обязательно вызови инструмент "
            "load_recommendation_context, используя application_id "
            "из задания. Не пытайся получить данные другим способом. "
            "Используй только факты из результата инструмента. "
            "Не выдумывай финансовые показатели, платёжеспособность, "
            "условия кредитования или вероятность одобрения. "
            "Не принимай решение об одобрении кредита. "
            "Верни только валидный JSON, без Markdown и HTML, "
            "по схеме: "
            '{"summary": "объяснение", '
            '"recommendations": ['
            '{"productId": "UUID", '
            '"reason": "обоснование", '
            '"matchedCriteria": ["критерий"]}'
            "]}. "
            "Не более трёх рекомендаций. "
            "productId должен совпадать с ID активного продукта. "
            "Если известная сумма или срок не подходят продукту, "
            "не рекомендуй его. Если подходящих продуктов нет, "
            "верни пустой массив recommendations. "
            "Все тексты пиши по-русски."
        ),
    )


def generate_recommendations(
    application_id: UUID | str,
    user_id: UUID | str,
) -> dict[str, Any]:
    """
    Публичный интерфейс агента.

    application_id — ID заявки.
    user_id — ID пользователя, полученный из авторизации FastAPI.

    Возвращает JSON-совместимый dict:
    {
        "summary": "...",
        "recommendations": [...]
    }
    """

    try:
        application_uuid = UUID(str(application_id))
        user_uuid = UUID(str(user_id))
    except (TypeError, ValueError, AttributeError) as exc:
        raise RecommendationApplicationNotFound from exc

    context_tool = LoadRecommendationContextTool(user_uuid)

    task = (
        "Подготовь рекомендации для заявки с application_id="
        f"{application_uuid}. "
        "Обязательно используй инструмент "
        "load_recommendation_context. "
        "Затем верни только JSON по указанной схеме."
    )

    try:
        agent = _make_agent(context_tool)
        raw_result = agent.run(task)
    except RecommendationGenerationError:
        raise
    except Exception as exc:
        raise RecommendationGenerationError(
            "Не удалось вызвать модель Hugging Face"
        ) from exc

    if context_tool.application_not_found:
        raise RecommendationApplicationNotFound

    if context_tool.context is None:
        raise RecommendationGenerationError(
            "Агент не загрузил контекст заявки"
        )

    context = context_tool.context
    products = context["activeProducts"]

    if not products:
        return {
            "summary": (
                "Сейчас нет активных кредитных продуктов для сравнения."
            ),
            "recommendations": [],
        }

    terms = [
        context["activeTerms"],
        context["originalTerms"],
    ]

    requested_amount = _find_number(
        terms,
        {
            "requestedamount",
            "loanamount",
            "creditamount",
            "requestedloanamount",
            "amount",
        },
    )

    requested_term = _find_number(
        terms,
        {
            "requestedtermmonths",
            "termmonths",
            "loantermmonths",
            "durationmonths",
            "term",
        },
    )

    result = _parse_json_result(raw_result)

    summary = result.get("summary")

    if not isinstance(summary, str) or not summary.strip():
        summary = (
            "Сравнение подготовлено по доступным сведениям заявки "
            "и параметрам кредитных продуктов."
        )

    product_by_id = {
        product["id"]: product for product in products
    }

    raw_recommendations = result.get("recommendations", [])

    if not isinstance(raw_recommendations, list):
        raise RecommendationGenerationError(
            "Поле recommendations должно быть массивом"
        )

    recommendations = []
    seen_product_ids: set[str] = set()

    for item in raw_recommendations:
        if not isinstance(item, dict):
            continue

        product_id = str(item.get("productId", ""))
        product = product_by_id.get(product_id)

        # Не принимаем неизвестные, неактивные и повторные продукты.
        if product is None or product_id in seen_product_ids:
            continue

        # Повторная проверка суммы на стороне бэкенда.
        if requested_amount is not None:
            if (
                product["minAmount"] is not None
                and requested_amount < product["minAmount"]
            ):
                continue

            if (
                product["maxAmount"] is not None
                and requested_amount > product["maxAmount"]
            ):
                continue

        # Повторная проверка срока на стороне бэкенда.
        if requested_term is not None:
            if (
                product["minTermMonths"] is not None
                and requested_term < product["minTermMonths"]
            ):
                continue

            if (
                product["maxTermMonths"] is not None
                and requested_term > product["maxTermMonths"]
            ):
                continue

        reason = item.get("reason")

        if not isinstance(reason, str) or not reason.strip():
            reason = (
                "Параметры продукта следует дополнительно "
                "сопоставить с потребностями компании."
            )

        criteria = item.get("matchedCriteria", [])

        if not isinstance(criteria, list):
            criteria = []

        criteria = [
            str(value)[:160]
            for value in criteria[:6]
            if isinstance(value, (str, int, float))
        ]

        recommendations.append({
            "productId": product_id,
            "productName": product["name"],
            "reason": reason[:1200],
            "matchedCriteria": criteria,
            "annualRate": product["annualRate"],
            "minAmount": product["minAmount"],
            "maxAmount": product["maxAmount"],
            "minTermMonths": product["minTermMonths"],
            "maxTermMonths": product["maxTermMonths"],
        })

        seen_product_ids.add(product_id)

        if len(recommendations) >= 3:
            break

    if not recommendations:
        summary = (
            "По известным параметрам заявки не удалось подтвердить "
            "подходящий продукт. Проверьте сумму и срок либо "
            "уточните условия с менеджером."
        )

    return {
        "summary": summary[:2000],
        "recommendations": recommendations,
    }