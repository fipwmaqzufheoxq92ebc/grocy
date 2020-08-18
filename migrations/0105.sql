DROP VIEW IF EXISTS stock_current_overview_opened;
CREATE VIEW IF NOT EXISTS stock_current_overview_opened
AS
SELECT id,
       stock_current.amount_opened AS                                                                   amount_opened,
       p.tare_weight AS                                                                                 tare_weight,
       p.enable_tare_weight_handling AS                                                                 enable_tare_weight_handling,
       stock_current.amount AS                                                                          amount,
       stock_current.product_id AS                                                                      product_id,
       stock_current.best_before_date AS                                                                best_before_date,
       EXISTS(SELECT id
              FROM (stock_missing_products_including_opened)
              WHERE id = stock_current.product_id) AS                                                   product_missing,
       (SELECT name FROM quantity_units WHERE quantity_units.id = p.qu_id_stock) AS                     qu_unit_name,
       (SELECT name_plural
        FROM quantity_units
        WHERE quantity_units.id = p.qu_id_stock) AS                                                     qu_unit_name_plural,
       p.name AS                                                                                        product_name,
       (SELECT name
        FROM product_groups
        WHERE product_groups.id = product_group_id) AS                                                  product_group_name,
       EXISTS(SELECT * FROM shopping_list WHERE shopping_list.product_id = stock_current.product_id) AS on_shopping_list,
       stock_current.factor_purchase_amount AS factor_purchase_amount,
       (SELECT name FROM quantity_units WHERE quantity_units.id = p.qu_id_purchase) AS                     qu_purchase_unit_name,
       (SELECT name_plural
        FROM quantity_units
        WHERE quantity_units.id = p.qu_id_purchase) AS                                                     qu_purchase_unit_name_plural
FROM (
         SELECT *
         FROM stock_current
         WHERE best_before_date IS NOT NULL
         UNION
         SELECT id,  0, 0, 0, 0, null, 0, 0, 0
         FROM stock_missing_products_including_opened
         WHERE id NOT IN (SELECT product_id FROM stock_current)
     ) AS stock_current
         LEFT JOIN products p ON stock_current.product_id = p.id;
DROP VIEW IF EXISTS stock_current_overview;

CREATE VIEW IF NOT EXISTS stock_current_overview
AS
SELECT id,
       stock_current.amount_opened                                                                   AS amount_opened,
       p.tare_weight                                                                                 AS tare_weight,
       p.enable_tare_weight_handling                                                                 AS enable_tare_weight_handling,
       stock_current.amount                                                                          AS amount,
       stock_current.product_id                                                                      AS product_id,
       stock_current.best_before_date                                                                AS best_before_date,
       EXISTS(SELECT id FROM (stock_missing_products) WHERE id = stock_current.product_id)           AS product_missing,
       (SELECT name FROM quantity_units WHERE quantity_units.id = p.qu_id_stock)                     AS qu_unit_name,
       (SELECT name_plural
        FROM quantity_units
        WHERE quantity_units.id = p.qu_id_stock)                                                     AS qu_unit_name_plural,
       p.name                                                                                        AS product_name,
       (SELECT name
        FROM product_groups
        WHERE product_groups.id = product_group_id)                                                  AS product_group_name,
       EXISTS(SELECT * FROM shopping_list WHERE shopping_list.product_id = stock_current.product_id) AS on_shopping_list,
       stock_current.factor_purchase_amount AS factor_purchase_amount
FROM (
         SELECT *
         FROM stock_current
         WHERE best_before_date IS NOT NULL
         UNION
         SELECT id,  0, 0, 0, 0, null, 0, 0, 0
         FROM stock_missing_products
         WHERE id NOT IN (SELECT product_id FROM stock_current)
     ) AS stock_current
         LEFT JOIN products p ON stock_current.product_id = p.id;