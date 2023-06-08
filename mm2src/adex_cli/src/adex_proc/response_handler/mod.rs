mod formatters;
mod orderbook;

use anyhow::{anyhow, Result};
use chrono::{TimeZone, Utc};
use common::io::{write_safe_io, writeln_safe_io, WriteSafeIO};
use itertools::Itertools;
use log::{error, info};
use mm2_number::bigdecimal::ToPrimitive;
use mm2_rpc::data::legacy::{BalanceResponse, CancelAllOrdersResponse, CoinInitResponse, FilteringOrder,
                            GetEnabledResponse, HistoricalOrder, MakerMatchForRpc, MakerOrderForMyOrdersRpc,
                            MakerOrderForRpc, MakerReservedForRpc, MatchBy, Mm2RpcResult, MmVersionResponse,
                            MyOrdersResponse, OrderConfirmationsSettings, OrderStatusResponse, OrderbookResponse,
                            OrdersHistoryResponse, PairWithDepth, SellBuyResponse, Status, TakerMatchForRpc,
                            TakerOrderForRpc};
use mm2_rpc::data::version2::BestOrdersV2Response;
use serde_json::Value as Json;
use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt::Debug;
use std::io::Write;
use std::ops::DerefMut;
use std::string::ToString;
use uuid::Uuid;

use term_table::row::Row;
use term_table::table_cell::{Alignment, TableCell};
use term_table::{Table as TermTable, TableStyle};

use super::OrderbookConfig;
use crate::adex_config::AdexConfig;
use crate::adex_proc::response_handler::formatters::smart_fraction_fmt::SmartFractionFmt;
use crate::error_anyhow;

const COMMON_INDENT: usize = 20;
const NESTED_INDENT: usize = 26;

pub(crate) trait ResponseHandler {
    fn print_response(&self, response: Json) -> Result<()>;
    fn debug_response<T: Debug + 'static>(&self, response: &T) -> Result<()>;
    fn on_orderbook_response<Cfg: AdexConfig + 'static>(
        &self,
        orderbook: OrderbookResponse,
        config: &Cfg,
        otderbook_config: OrderbookConfig,
    ) -> Result<()>;
    fn on_get_enabled_response(&self, enabled: &Mm2RpcResult<GetEnabledResponse>) -> Result<()>;
    fn on_version_response(&self, response: &MmVersionResponse) -> Result<()>;
    fn on_enable_response(&self, response: &CoinInitResponse) -> Result<()>;
    fn on_balance_response(&self, response: &BalanceResponse) -> Result<()>;
    fn on_sell_response(&self, response: &Mm2RpcResult<SellBuyResponse>) -> Result<()>;
    fn on_buy_response(&self, response: &Mm2RpcResult<SellBuyResponse>) -> Result<()>;
    fn on_stop_response(&self, response: &Mm2RpcResult<Status>) -> Result<()>;
    fn on_cancel_order_response(&self, response: &Mm2RpcResult<Status>) -> Result<()>;
    fn on_cancel_all_response(&self, response: &Mm2RpcResult<CancelAllOrdersResponse>) -> Result<()>;
    fn on_order_status(&self, response: &OrderStatusResponse) -> Result<()>;
    fn on_best_orders(&self, best_orders: BestOrdersV2Response, show_orig_tickets: bool) -> Result<()>;
    fn on_my_orders(&self, my_orders: MyOrdersResponse) -> Result<()>;
    fn on_set_price(&self, order: MakerOrderForRpc) -> Result<()>;
    fn on_orderbook_depth(&self, orderbook_depth: Vec<PairWithDepth>) -> Result<()>;
    fn on_orders_history(&self, order_history: OrdersHistoryResponse, is_detailed: bool) -> Result<()>;
}

pub(crate) struct ResponseHandlerImpl<'a> {
    pub writer: RefCell<&'a mut dyn Write>,
}

impl<'a> ResponseHandler for ResponseHandlerImpl<'a> {
    fn print_response(&self, result: Json) -> Result<()> {
        let mut binding = self.writer.borrow_mut();
        let writer = binding.deref_mut();
        let object = result
            .as_object()
            .ok_or_else(|| error_anyhow!("Failed to cast result as object"))?;

        object
            .iter()
            .for_each(|value| writeln_safe_io!(writer, "{}: {:?}", value.0, value.1));
        Ok(())
    }

    fn debug_response<T: Debug + 'static>(&self, response: &T) -> Result<()> {
        info!("{response:?}");
        Ok(())
    }

    fn on_orderbook_response<Cfg: AdexConfig + 'static>(
        &self,
        orderbook: OrderbookResponse,
        config: &Cfg,
        otderbook_config: OrderbookConfig,
    ) -> Result<()> {
        let mut writer = self.writer.borrow_mut();

        let base_vol_head = "Volume: ".to_string() + &orderbook.base;
        let rel_price_head = "Price: ".to_string() + &orderbook.rel;
        writeln_safe_io!(
            writer,
            "{}",
            orderbook::AskBidRow::new(
                base_vol_head.as_str(),
                rel_price_head.as_str(),
                "Uuid",
                "Min volume",
                "Max volume",
                "Age(sec.)",
                "Public",
                "Address",
                "Order conf (bc,bn:rc,rn)",
                &otderbook_config
            )
        );

        let price_prec = config.orderbook_price_precision();
        let vol_prec = config.orderbook_volume_precision();

        if orderbook.asks.is_empty() {
            writeln_safe_io!(
                writer,
                "{}",
                orderbook::AskBidRow::new("", "No asks found", "", "", "", "", "", "", "", &otderbook_config)
            );
        } else {
            let skip = orderbook
                .asks
                .len()
                .checked_sub(otderbook_config.asks_limit.unwrap_or(usize::MAX))
                .unwrap_or_default();

            orderbook
                .asks
                .iter()
                .sorted_by(orderbook::cmp_asks)
                .skip(skip)
                .map(|entry| orderbook::AskBidRow::from_orderbook_entry(entry, vol_prec, price_prec, &otderbook_config))
                .for_each(|row: orderbook::AskBidRow| writeln_safe_io!(writer, "{}", row));
        }
        writeln_safe_io!(writer, "{}", orderbook::AskBidRow::new_delimiter(&otderbook_config));

        if orderbook.bids.is_empty() {
            writeln_safe_io!(
                writer,
                "{}",
                orderbook::AskBidRow::new("", "No bids found", "", "", "", "", "", "", "", &otderbook_config)
            );
        } else {
            orderbook
                .bids
                .iter()
                .sorted_by(orderbook::cmp_bids)
                .take(otderbook_config.bids_limit.unwrap_or(usize::MAX))
                .map(|entry| orderbook::AskBidRow::from_orderbook_entry(entry, vol_prec, price_prec, &otderbook_config))
                .for_each(|row: orderbook::AskBidRow| writeln_safe_io!(writer, "{}", row));
        }
        Ok(())
    }

    fn on_get_enabled_response(&self, enabled: &Mm2RpcResult<GetEnabledResponse>) -> Result<()> {
        let mut writer = self.writer.borrow_mut();
        writeln_safe_io!(writer, "{:8} {}", "Ticker", "Address");
        for row in &enabled.result {
            writeln_safe_io!(writer, "{:8} {}", row.ticker, row.address);
        }
        Ok(())
    }

    fn on_version_response(&self, response: &MmVersionResponse) -> Result<()> {
        let mut writer = self.writer.borrow_mut();
        writeln_safe_io!(writer, "Version: {}", response.result);
        writeln_safe_io!(writer, "Datetime: {}", response.datetime);
        Ok(())
    }

    fn on_enable_response(&self, response: &CoinInitResponse) -> Result<()> {
        let mut writer = self.writer.borrow_mut();
        writeln_safe_io!(
            writer,
            "coin: {}\naddress: {}\nbalance: {}\nunspendable_balance: {}\nrequired_confirmations: {}\nrequires_notarization: {}",
            response.coin,
            response.address,
            response.balance,
            response.unspendable_balance,
            response.required_confirmations,
            if response.requires_notarization { "Yes" } else { "No" }
        );
        if let Some(mature_confirmations) = response.mature_confirmations {
            writeln_safe_io!(writer, "mature_confirmations: {}", mature_confirmations);
        }
        Ok(())
    }

    fn on_balance_response(&self, response: &BalanceResponse) -> Result<()> {
        writeln_safe_io!(
            self.writer.borrow_mut(),
            "coin: {}\nbalance: {}\nunspendable: {}\naddress: {}",
            response.coin,
            response.balance,
            response.unspendable_balance,
            response.address
        );
        Ok(())
    }

    fn on_sell_response(&self, response: &Mm2RpcResult<SellBuyResponse>) -> Result<()> {
        writeln_safe_io!(self.writer.borrow_mut(), "{}", response.request.uuid);
        Ok(())
    }

    fn on_buy_response(&self, response: &Mm2RpcResult<SellBuyResponse>) -> Result<()> {
        writeln_safe_io!(self.writer.borrow_mut(), "{}", response.request.uuid);
        Ok(())
    }

    fn on_stop_response(&self, response: &Mm2RpcResult<Status>) -> Result<()> {
        writeln_safe_io!(self.writer.borrow_mut(), "Service stopped: {}", response.result);
        Ok(())
    }

    fn on_cancel_order_response(&self, response: &Mm2RpcResult<Status>) -> Result<()> {
        match response.result {
            Status::Success => writeln_safe_io!(self.writer.borrow_mut(), "Order cancelled"),
        }
        Ok(())
    }

    fn on_cancel_all_response(&self, response: &Mm2RpcResult<CancelAllOrdersResponse>) -> Result<()> {
        let cancelled = &response.result.cancelled;
        let mut writer = self.writer.borrow_mut();
        if cancelled.is_empty() {
            writeln_safe_io!(writer, "No orders found to be cancelled");
        } else {
            writeln_safe_io!(writer, "Cancelled: {}", cancelled.iter().join(", "));
        }

        let currently_matched = &response.result.currently_matching;
        if !currently_matched.is_empty() {
            writeln_safe_io!(writer, "Currently matched: {}", currently_matched.iter().join(", "));
        }
        Ok(())
    }

    fn on_order_status(&self, response: &OrderStatusResponse) -> Result<()> {
        let mut binding = self.writer.borrow_mut();
        let mut writer: &mut dyn Write = binding.deref_mut();
        match response {
            OrderStatusResponse::Maker(maker_status) => Self::write_maker_order_for_my_orders(writer, maker_status),
            OrderStatusResponse::Taker(taker_status) => self.print_taker_order(&mut writer, taker_status),
        }
    }

    fn on_best_orders(&self, best_orders: BestOrdersV2Response, show_orig_tickets: bool) -> Result<()> {
        let mut writer = self.writer.borrow_mut();
        if show_orig_tickets {
            writeln_field!(writer, "Original tickers", "", 0);
            for (coin, ticker) in best_orders.original_tickers {
                writeln_field!(writer, coin, ticker.iter().join(","), 8);
            }
            return Ok(());
        }

        let mut term_table = TermTable::with_rows(vec![Row::new(vec![
            TableCell::new(""),
            TableCell::new("Price"),
            TableCell::new("Uuid"),
            TableCell::new("Base vol(min:max)"),
            TableCell::new("Rel vol(min:max)"),
            TableCell::new("Address"),
            TableCell::new("Confirmation"),
        ])]);
        term_table.style = TableStyle::thin();
        term_table.separate_rows = false;
        for (coin, data) in best_orders.orders.iter().sorted_by_key(|p| p.0) {
            term_table.add_row(Row::new(vec![TableCell::new_with_alignment(coin, 7, Alignment::Left)]));
            for order in data.iter().sorted_by_key(|o| o.uuid) {
                term_table.add_row(Row::new(vec![
                    TableCell::new(if order.is_mine { "*" } else { "" }),
                    TableCell::new(format_ratio(&order.price.rational, 2, 5)?),
                    TableCell::new(order.uuid),
                    TableCell::new(format!(
                        "{}:{}",
                        format_ratio(&order.base_min_volume.rational, 2, 5)?,
                        format_ratio(&order.base_max_volume.rational, 2, 5)?
                    )),
                    TableCell::new(format!(
                        "{}:{}",
                        format_ratio(&order.rel_min_volume.rational, 2, 5)?,
                        format_ratio(&order.rel_max_volume.rational, 2, 5)?
                    )),
                    TableCell::new(&order.address),
                    TableCell::new(
                        &order
                            .conf_settings
                            .map_or_else(|| "none".to_string(), |value| format_confirmation_settings(&value)),
                    ),
                ]));
            }
        }
        write_safe_io!(writer, "{}", term_table.render());

        Ok(())
    }

    fn on_my_orders(&self, my_orders: MyOrdersResponse) -> Result<()> {
        let mut writer = self.writer.borrow_mut();
        let writer: &mut dyn Write = writer.deref_mut();
        writeln_safe_io!(writer, "{}", Self::format_taker_orders_table(&my_orders.taker_orders)?);
        writeln_safe_io!(writer, "{}", Self::format_maker_orders_table(&my_orders.maker_orders)?);
        Ok(())
    }

    fn on_set_price(&self, order: MakerOrderForRpc) -> Result<()> {
        let mut writer = self.writer.borrow_mut();
        let writer: &mut dyn Write = writer.deref_mut();
        writeln_field!(writer, "Maker order", "", 0);
        Self::write_maker_order(writer, &order)?;
        Self::write_maker_matches(writer, &order.matches)?;
        writeln_safe_io!(writer, "");
        Ok(())
    }

    fn on_orderbook_depth(&self, mut orderbook_depth: Vec<PairWithDepth>) -> Result<()> {
        let mut term_table = TermTable::with_rows(vec![Row::new(vec![
            TableCell::new(""),
            TableCell::new_with_alignment_and_padding("Bids", 1, Alignment::Left, false),
            TableCell::new_with_alignment_and_padding("Asks", 1, Alignment::Left, false),
        ])]);
        term_table.style = TableStyle::empty();
        term_table.separate_rows = false;
        term_table.has_bottom_boarder = false;
        term_table.has_top_boarder = false;
        orderbook_depth.drain(..).for_each(|data| {
            term_table.add_row(Row::new(vec![
                TableCell::new_with_alignment_and_padding(
                    format!("{}/{}:", data.pair.0, data.pair.1),
                    1,
                    Alignment::Right,
                    false,
                ),
                TableCell::new_with_alignment_and_padding(data.depth.bids, 1, Alignment::Left, false),
                TableCell::new_with_alignment_and_padding(data.depth.asks, 1, Alignment::Left, false),
            ]))
        });
        let mut writer = self.writer.borrow_mut();
        let writer: &mut dyn Write = writer.deref_mut();
        write_safe_io!(writer, "{}", term_table.render().replace("\0", ""));
        Ok(())
    }

    fn on_orders_history(&self, order_history: OrdersHistoryResponse, is_detailed: bool) -> Result<()> {
        let mut fo_table = term_table_blank();
        fo_table.add_row(Self::filtering_order_header_row());

        for order in order_history.orders {
            fo_table.add_row(Self::filtering_order_row(&order)?);
        }

        let mut writer = self.writer.borrow_mut();
        let writer: &mut dyn Write = writer.deref_mut();
        writeln_safe_io!(writer, "{}", fo_table.render());
        if is_detailed {
            let mut detailed_table = term_table_blank();
            detailed_table.add_row()
        }

        Ok(())
    }
}

fn term_table_blank() -> TermTable<'static> {
    let mut term_table = TermTable::new();
    term_table.style = TableStyle::thin();
    term_table.separate_rows = false;
    term_table.has_bottom_boarder = false;
    term_table.has_top_boarder = false;
    term_table
}

impl ResponseHandlerImpl<'_> {
    fn write_maker_order_for_my_orders(writer: &mut dyn Write, maker_status: &MakerOrderForMyOrdersRpc) -> Result<()> {
        let order = &maker_status.order;
        Self::write_maker_order(writer, order)?;

        writeln_field!(writer, "cancellable", maker_status.cancellable, COMMON_INDENT);
        writeln_field!(
            writer,
            "available_amount",
            format_ratio(&maker_status.available_amount, 2, 5)?,
            COMMON_INDENT
        );

        Self::write_maker_matches(writer, &order.matches)?;
        writeln_safe_io!(writer, "");
        Ok(())
    }

    fn write_maker_order(writer: &mut dyn Write, order: &MakerOrderForRpc) -> Result<()> {
        writeln_field!(writer, "base", order.base, COMMON_INDENT);
        writeln_field!(writer, "rel", order.rel, COMMON_INDENT);
        writeln_field!(writer, "price", format_ratio(&order.price_rat, 2, 5)?, COMMON_INDENT);
        writeln_field!(writer, "uuid", order.uuid, COMMON_INDENT);
        writeln_field!(writer, "created at", format_datetime(order.created_at)?, COMMON_INDENT);

        if let Some(updated_at) = order.updated_at {
            writeln_field!(writer, "updated at", format_datetime(updated_at)?, COMMON_INDENT);
        }
        writeln_field!(
            writer,
            "max_base_vol",
            format_ratio(&order.max_base_vol_rat, 2, 5)?,
            COMMON_INDENT
        );
        writeln_field!(
            writer,
            "min_base_vol",
            format_ratio(&order.min_base_vol_rat, 2, 5)?,
            COMMON_INDENT
        );
        writeln_field!(
            writer,
            "swaps",
            if order.started_swaps.is_empty() {
                "empty".to_string()
            } else {
                order.started_swaps.iter().join(", ")
            },
            COMMON_INDENT
        );

        if let Some(ref conf_settings) = order.conf_settings {
            writeln_field!(
                writer,
                "conf_settings",
                format_confirmation_settings(conf_settings),
                COMMON_INDENT
            );
        }
        if let Some(ref changes_history) = order.changes_history {
            writeln_field!(
                writer,
                "changes_history",
                changes_history
                    .iter()
                    .map(|val| format_historical_changes(val, ", ").unwrap_or_else(|_| "error".into()))
                    .join(", "),
                COMMON_INDENT
            );
        }
        Ok(())
    }

    fn write_maker_matches(writer: &mut dyn Write, matches: &HashMap<Uuid, MakerMatchForRpc>) -> Result<()> {
        if matches.is_empty() {
            return Ok(());
        }
        for (uuid, m) in matches {
            Self::write_maker_match(writer, uuid, m)?
        }
        Ok(())
    }

    fn write_maker_match(writer: &mut dyn Write, uuid: &Uuid, m: &MakerMatchForRpc) -> Result<()> {
        let (req, reserved, connect, connected) = (&m.request, &m.reserved, &m.connect, &m.connected);
        writeln_field!(writer, "uuid", uuid, NESTED_INDENT);
        writeln_field!(writer, "req.uuid", req.uuid, NESTED_INDENT);
        write_base_rel!(writer, req, NESTED_INDENT);
        writeln_field!(
            writer,
            "req.match_by",
            format_match_by(&req.match_by, ", "),
            NESTED_INDENT
        );
        writeln_field!(writer, "req.action", req.action, NESTED_INDENT);
        write_confirmation_settings!(writer, req, NESTED_INDENT);
        writeln_field!(
            writer,
            "req.(sender, dest)",
            format!("{},{}", req.sender_pubkey, req.dest_pub_key),
            NESTED_INDENT
        );
        Self::write_maker_reserved_for_rpc(writer, reserved);

        if let Some(ref connected) = connected {
            write_connected!(writer, connected, NESTED_INDENT);
        }

        if let Some(ref connect) = connect {
            write_connected!(writer, connect, NESTED_INDENT);
        }

        write_field!(writer, "last_updated", format_datetime(m.last_updated)?, NESTED_INDENT);
        Ok(())
    }

    fn maker_order_header_row() -> Row<'static> {
        Row::new(vec![
            TableCell::new("base,rel"),
            TableCell::new("price"),
            TableCell::new("uuid"),
            TableCell::new("created at,\nupdated at"),
            TableCell::new("min base vol,\nmax base vol"),
            TableCell::new("swaps"),
            TableCell::new("conf_settings"),
            TableCell::new("history changes"),
            TableCell::new("ob ticker base,\nrel"),
        ])
    }

    fn maker_order_row(order: &MakerOrderForRpc) -> Result<Vec<Row>> {
        let mut rows = vec![Row::new(vec![
            TableCell::new(format!("{},{}", order.base, order.rel)),
            TableCell::new(format_ratio(&order.price_rat, 2, 5)?),
            TableCell::new(order.uuid),
            TableCell::new(format!(
                "{},\n{}",
                format_datetime(order.created_at)?,
                order.updated_at.map_or(Ok("".to_string()), format_datetime)?
            )),
            TableCell::new(format!(
                "{},\n{}",
                format_ratio(&order.min_base_vol_rat, 2, 5)?,
                format_ratio(&order.max_base_vol_rat, 2, 5)?
            )),
            TableCell::new(if order.started_swaps.is_empty() {
                "empty".to_string()
            } else {
                order.started_swaps.iter().join(",\n")
            }),
            TableCell::new(
                order
                    .conf_settings
                    .map_or_else(|| "none".to_string(), |value| format_confirmation_settings(&value)),
            ),
            TableCell::new(order.changes_history.as_ref().map_or_else(
                || "none".to_string(),
                |val| {
                    val.iter()
                        .map(|val| format_historical_changes(val, "\n").unwrap_or_else(|_| "error".into()))
                        .join(",\n")
                },
            )),
            TableCell::new(format!(
                "{}\n{}",
                order
                    .base_orderbook_ticker
                    .as_ref()
                    .map_or_else(|| "none".to_string(), String::clone),
                order
                    .rel_orderbook_ticker
                    .as_ref()
                    .map_or_else(|| "none".to_string(), String::clone)
            )),
        ])];

        if order.matches.is_empty() {
            return Ok(rows);
        }
        rows.push(Row::new(vec![TableCell::new_with_col_span("matches", 10)]));
        for (uuid, m) in &order.matches {
            let mut matches_str = Vec::new();
            let mut bbox: Box<dyn Write> = Box::new(&mut matches_str);
            Self::write_maker_match(bbox.as_mut(), uuid, m)?;
            drop(bbox);
            rows.push(Row::new(vec![TableCell::new_with_col_span(
                String::from_utf8(matches_str).unwrap(),
                10,
            )]));
        }
        Ok(rows)
    }

    fn taker_order_header_row() -> Row<'static> {
        Row::new(vec![
            TableCell::new("action\nbase(vol),rel(vol)"),
            TableCell::new("uuid, sender, dest"),
            TableCell::new("type,created_at\nconfirmation"),
            TableCell::new("match_by"),
            TableCell::new("base,rel\norderbook ticker"),
            TableCell::new("cancellable"),
        ])
    }

    fn taker_order_row(taker_order: &TakerOrderForRpc) -> Result<Vec<Row>> {
        let req = &taker_order.request;
        let mut rows = vec![Row::new(vec![
            TableCell::new(format!(
                "{}\n{}({}),{}({})",
                req.action,
                req.base,
                format_ratio(&req.base_amount, 2, 5)?,
                req.rel,
                format_ratio(&req.rel_amount, 2, 5)?
            )),
            TableCell::new(format!("{}\n{}\n{}", req.uuid, req.sender_pubkey, req.dest_pub_key)),
            TableCell::new(format!(
                "{}\n{}\n{}",
                taker_order.order_type,
                format_datetime(taker_order.created_at)?,
                req.conf_settings
                    .as_ref()
                    .map_or_else(|| "none".to_string(), format_confirmation_settings),
            )),
            TableCell::new(format_match_by(&req.match_by, "\n")),
            TableCell::new(format!(
                "{}\n{}",
                taker_order
                    .base_orderbook_ticker
                    .as_ref()
                    .map_or_else(|| "none".to_string(), String::clone),
                taker_order
                    .rel_orderbook_ticker
                    .as_ref()
                    .map_or_else(|| "none".to_string(), String::clone)
            )),
            TableCell::new(taker_order.cancellable),
        ])];

        if taker_order.matches.is_empty() {
            return Ok(rows);
        }
        rows.push(Row::new(vec![TableCell::new_with_col_span("matches", 6)]));
        for (uuid, m) in taker_order.matches.iter() {
            let mut matches_str = Vec::new();
            let mut buf: Box<dyn Write> = Box::new(&mut matches_str);
            Self::write_taker_match(buf.as_mut(), uuid, m)?;
            drop(buf);
            rows.push(Row::new(vec![TableCell::new_with_col_span(
                String::from_utf8(matches_str)
                    .map_err(|err| error_anyhow!("Failed to get string from taker order matches_str: {err}"))?,
                6,
            )]));
        }

        Ok(rows)
    }

    fn format_maker_orders_table(maker_orders: &HashMap<Uuid, MakerOrderForMyOrdersRpc>) -> Result<String> {
        let mut buff = Vec::new();
        let mut writer: Box<dyn Write> = Box::new(&mut buff);

        if maker_orders.is_empty() {
            writeln_field!(writer, "Maker orders", "empty", COMMON_INDENT);
        } else {
            writeln_field!(writer, "Maker orders", "", COMMON_INDENT);
            let mut table = TermTable::new();
            table.style = TableStyle::thin();
            table.separate_rows = false;
            table.add_row(ResponseHandlerImpl::maker_order_for_my_orders_header_row());

            for (_, maker_order) in maker_orders.iter().sorted_by_key(|(uuid, _)| *uuid) {
                for row in ResponseHandlerImpl::maker_order_for_my_orders_row(maker_order)? {
                    table.add_row(row);
                }
            }
            write_safe_io!(writer, "{}", table.render());
        }
        drop(writer);
        String::from_utf8(buff).map_err(|error| error_anyhow!("Failed to format maker orders table: {error}"))
    }

    fn format_taker_orders_table(taker_orders: &HashMap<Uuid, TakerOrderForRpc>) -> Result<String> {
        let mut buff = Vec::new();
        let mut writer: Box<dyn Write> = Box::new(&mut buff);

        if taker_orders.is_empty() {
            writeln_field!(writer, "Taker orders", "empty", COMMON_INDENT);
        } else {
            writeln_field!(writer, "Taker orders", "", COMMON_INDENT);
            let mut table = TermTable::new();
            table.style = TableStyle::thin();
            table.separate_rows = false;
            table.add_row(ResponseHandlerImpl::taker_order_header_row());
            for (_, taker_order) in taker_orders.iter().sorted_by_key(|(uuid, _)| *uuid) {
                for row in ResponseHandlerImpl::taker_order_row(taker_order)? {
                    table.add_row(row);
                }
            }
            write_safe_io!(writer, "{}", table.render());
        }
        drop(writer);
        String::from_utf8(buff).map_err(|error| error_anyhow!("Failed to format maker orders table: {error}"))
    }

    fn maker_order_for_my_orders_header_row() -> Row<'static> {
        Row::new(vec![
            TableCell::new("base,rel"),
            TableCell::new("price"),
            TableCell::new("uuid"),
            TableCell::new("created at,\nupdated at"),
            TableCell::new("min base vol,\nmax base vol"),
            TableCell::new("cancellable"),
            TableCell::new("available\namount"),
            TableCell::new("swaps"),
            TableCell::new("conf_settings"),
            TableCell::new("history changes"),
        ])
    }

    fn maker_order_for_my_orders_row(maker_order: &MakerOrderForMyOrdersRpc) -> Result<Vec<Row>> {
        let order = &maker_order.order;
        let mut rows = vec![Row::new(vec![
            TableCell::new(format!("{},{}", order.base, order.rel)),
            TableCell::new(format_ratio(&order.price_rat, 2, 5)?),
            TableCell::new(order.uuid),
            TableCell::new(format!(
                "{},\n{}",
                format_datetime(order.created_at)?,
                order.updated_at.map_or(Ok("".to_string()), format_datetime)?
            )),
            TableCell::new(format!(
                "{},\n{}",
                format_ratio(&order.min_base_vol_rat, 2, 5)?,
                format_ratio(&order.max_base_vol_rat, 2, 5)?
            )),
            TableCell::new(maker_order.cancellable),
            TableCell::new(format_ratio(&maker_order.available_amount, 2, 5)?),
            TableCell::new(if order.started_swaps.is_empty() {
                "empty".to_string()
            } else {
                order.started_swaps.iter().join(",\n")
            }),
            TableCell::new(
                order
                    .conf_settings
                    .map_or_else(|| "none".to_string(), |value| format_confirmation_settings(&value)),
            ),
            TableCell::new(order.changes_history.as_ref().map_or_else(
                || "none".to_string(),
                |val| {
                    val.iter()
                        .map(|val| format_historical_changes(val, "\n").unwrap_or_else(|_| "error".into()))
                        .join(",\n")
                },
            )),
        ])];

        if order.matches.is_empty() {
            return Ok(rows);
        }
        rows.push(Row::new(vec![TableCell::new_with_col_span("matches", 10)]));
        for (uuid, m) in &order.matches {
            let mut matches_str = Vec::new();
            let mut bbox: Box<dyn Write> = Box::new(&mut matches_str);
            Self::write_maker_match(bbox.as_mut(), uuid, m)?;
            drop(bbox);
            rows.push(Row::new(vec![TableCell::new_with_col_span(
                String::from_utf8(matches_str).unwrap(),
                10,
            )]));
        }
        Ok(rows)
    }

    fn print_taker_order(&self, writer: &mut dyn Write, taker_status: &TakerOrderForRpc) -> Result<()> {
        let req = &taker_status.request;

        writeln_field!(writer, "uuid", req.uuid, COMMON_INDENT);
        write_base_rel!(writer, req, COMMON_INDENT);
        writeln_field!(writer, "req.action", req.action, COMMON_INDENT);
        writeln_field!(
            writer,
            "req.(sender, dest)",
            format!("{}, {}", req.sender_pubkey, req.dest_pub_key),
            COMMON_INDENT
        );
        writeln_field!(
            writer,
            "req.match_by",
            format_match_by(&req.match_by, "\n"),
            COMMON_INDENT
        );
        write_confirmation_settings!(writer, req, COMMON_INDENT);
        writeln_field!(
            writer,
            "created_at",
            format_datetime(taker_status.created_at)?,
            COMMON_INDENT
        );
        writeln_field!(writer, "order_type", taker_status.order_type, COMMON_INDENT);
        writeln_field!(writer, "cancellable", taker_status.cancellable, COMMON_INDENT);
        write_field_option!(
            writer,
            "base_ob_ticker",
            taker_status.base_orderbook_ticker,
            COMMON_INDENT
        );
        write_field_option!(
            writer,
            "rel_ob_ticker",
            taker_status.rel_orderbook_ticker,
            COMMON_INDENT
        );
        Self::write_taker_matches(writer, &taker_status.matches)?;
        Ok(())
    }

    fn write_taker_matches(writer: &mut dyn Write, matches: &HashMap<Uuid, TakerMatchForRpc>) -> Result<()> {
        if matches.is_empty() {
            //writeln_field!(writer, "matches", "empty", COMMON_INDENT);
            return Ok(());
        }
        writeln_field!(writer, "matches", "", COMMON_INDENT);
        for (uuid, m) in matches {
            Self::write_taker_match(writer, uuid, m)?;
        }
        Ok(())
    }

    fn write_taker_match(writer: &mut dyn Write, uuid: &Uuid, m: &TakerMatchForRpc) -> Result<()> {
        let (reserved, connect, connected) = (&m.reserved, &m.connect, &m.connected);
        writeln_field!(writer, "uuid", uuid, NESTED_INDENT);
        Self::write_maker_reserved_for_rpc(writer, reserved);
        writeln_field!(writer, "last_updated", m.last_updated, NESTED_INDENT);
        write_connected!(writer, connect, NESTED_INDENT);
        if let Some(ref connected) = connected {
            write_connected!(writer, connected, NESTED_INDENT);
        }
        Ok(())
    }

    fn write_maker_reserved_for_rpc(writer: &mut dyn Write, reserved: &MakerReservedForRpc) {
        write_base_rel!(writer, reserved, NESTED_INDENT);
        writeln_field!(
            writer,
            "reserved.(taker, maker)",
            format!("{},{}", reserved.taker_order_uuid, reserved.maker_order_uuid),
            NESTED_INDENT
        );
        writeln_field!(
            writer,
            "reserved.(sender, dest)",
            format!("{},{}", reserved.sender_pubkey, reserved.dest_pub_key),
            NESTED_INDENT
        );
        write_confirmation_settings!(writer, reserved, NESTED_INDENT);
    }

    fn filtering_order_header_row() -> Row<'static> {
        Row::new(vec![
            TableCell::new_with_alignment_and_padding("uuid", 1, Alignment::Left, false),
            TableCell::new_with_alignment_and_padding("Type", 1, Alignment::Left, false),
            TableCell::new_with_alignment_and_padding("Action", 1, Alignment::Left, false),
            TableCell::new_with_alignment_and_padding("Base", 1, Alignment::Left, false),
            TableCell::new_with_alignment_and_padding("Rel", 1, Alignment::Left, false),
            TableCell::new_with_alignment_and_padding("Volume", 1, Alignment::Left, false),
            TableCell::new_with_alignment_and_padding("Price", 1, Alignment::Left, false),
            TableCell::new_with_alignment_and_padding("Status", 1, Alignment::Left, false),
            TableCell::new_with_alignment_and_padding("Created", 1, Alignment::Left, false),
            TableCell::new_with_alignment_and_padding("Updated", 1, Alignment::Left, false),
            TableCell::new_with_alignment_and_padding("Was taker", 1, Alignment::Left, false),
        ])
    }

    fn filtering_order_row(order: &FilteringOrder) -> Result<Row<'static>> {
        Ok(Row::new(vec![
            TableCell::new_with_alignment_and_padding(&order.uuid, 1, Alignment::Left, false),
            TableCell::new_with_alignment_and_padding(&order.order_type, 1, Alignment::Left, false),
            TableCell::new_with_alignment_and_padding(&order.initial_action, 1, Alignment::Left, false),
            TableCell::new_with_alignment_and_padding(&order.base, 1, Alignment::Left, false),
            TableCell::new_with_alignment_and_padding(&order.rel, 1, Alignment::Left, false),
            TableCell::new_with_alignment_and_padding(format_f64(order.volume, 2, 5)?, 1, Alignment::Left, false),
            TableCell::new_with_alignment_and_padding(format_f64(order.price, 2, 5)?, 1, Alignment::Left, false),
            TableCell::new_with_alignment_and_padding(&order.status, 1, Alignment::Left, false),
            TableCell::new_with_alignment_and_padding(
                format_datetime(order.created_at as u64)?,
                1,
                Alignment::Left,
                false,
            ),
            TableCell::new_with_alignment_and_padding(
                format_datetime(order.last_updated as u64)?,
                1,
                Alignment::Left,
                false,
            ),
            TableCell::new_with_alignment_and_padding(order.was_taker != 0, 1, Alignment::Left, false),
        ]))
    }
}

mod macros {
    #[macro_export]
    macro_rules! writeln_field {
        ($writer:ident, $name:expr, $value:expr, $width:expr) => {
            writeln_safe_io!($writer, "{:>width$}: {}", $name, $value, width = $width);
        };
    }

    #[macro_export]
    macro_rules! write_field {
        ($writer:ident, $name:expr, $value:expr, $width:expr) => {
            write_safe_io!($writer, "{:>width$}: {}", $name, $value, width = $width);
        };
    }

    #[macro_export]
    macro_rules! write_field_option {
        ($writer:ident, $name:expr, $value:expr, $width:expr) => {
            if let Some(ref value) = $value {
                writeln_safe_io!($writer, "{:>width$}: {}", $name, value, width = $width);
            }
        };
    }

    #[macro_export]
    macro_rules! write_confirmation_settings {
        ($writer:ident, $host:ident, $width:ident) => {
            if $host.conf_settings.is_some() {
                let output = format_confirmation_settings($host.conf_settings.as_ref().unwrap());
                writeln_field!(
                    $writer,
                    concat!(stringify!($host), ".conf_settings"),
                    output,
                    $width
                );
            }
        };
    }

    #[macro_export]
    macro_rules! write_base_rel {
        ($writer:ident, $host:expr, $width:ident) => {
            writeln_field!(
                $writer,
                concat!(stringify!($host), ".(base,rel)"),
                format!(
                    "{}({}), {}({})",
                    $host.base, $host.base_amount, $host.rel, $host.rel_amount
                ),
                $width
            );
        };
    }

    #[macro_export]
    macro_rules! write_connected {
        ($writer:ident, $connected:expr, $width:ident) => {
            writeln_field!(
                $writer,
                concat!(stringify!($connected), ".(taker,maker)"),
                format!("{},{}", $connected.taker_order_uuid, $connected.maker_order_uuid),
                $width
            );
            writeln_field!(
                $writer,
                concat!(stringify!($connected), ".(sender, dest)"),
                format!("{},{}", $connected.sender_pubkey, $connected.dest_pub_key),
                $width
            );
        };
    }

    pub use {write_base_rel, write_confirmation_settings, write_connected, write_field, writeln_field};
}

use crate::write_field_option;
use macros::{write_base_rel, write_confirmation_settings, write_connected, write_field, writeln_field};

fn format_match_by(match_by: &MatchBy, delimiter: &str) -> String {
    match match_by {
        MatchBy::Any => "Any".to_string(),
        MatchBy::Orders(orders) => orders.iter().sorted().join(delimiter),
        MatchBy::Pubkeys(pubkeys) => pubkeys.iter().sorted().join(delimiter),
    }
}

fn format_confirmation_settings(settings: &OrderConfirmationsSettings) -> String {
    format!(
        "{},{}:{},{}",
        settings.base_confs, settings.base_nota, settings.rel_confs, settings.rel_nota
    )
}

fn format_datetime(datetime: u64) -> Result<String> {
    let datetime = Utc
        .timestamp_opt((datetime / 1000) as i64, 0)
        .single()
        .ok_or_else(|| error_anyhow!("Failed to get datetime formatted datetime"))?;
    Ok(format!("{}", datetime.format("%y-%m-%d %H:%M:%S")))
}

fn format_ratio<T: ToPrimitive + Debug>(rational: &T, min_fract: usize, max_fract: usize) -> Result<String> {
    format_f64(
        rational
            .to_f64()
            .ok_or_else(|| error_anyhow!("Failed to cast rational to f64: {rational:?}"))?,
        min_fract,
        max_fract,
    )
}

fn format_f64(rational: f64, min_fract: usize, max_fract: usize) -> Result<String> {
    Ok(SmartFractionFmt::new(min_fract, max_fract, rational)
        .map_err(|_| error_anyhow!("Failed to create smart_fraction_fmt"))?
        .to_string())
}

fn format_historical_changes(historical_order: &HistoricalOrder, delimiter: &str) -> Result<String> {
    let mut result = vec![];

    if let Some(ref min_base_vol) = historical_order.min_base_vol {
        result.push(format!("min_base_vol: {}", format_ratio(min_base_vol, 2, 5)?,))
    }
    if let Some(ref max_base_vol) = historical_order.max_base_vol {
        result.push(format!("max_base_vol: {}", format_ratio(max_base_vol, 2, 5)?,))
    }
    if let Some(ref price) = historical_order.price {
        result.push(format!("price: {}", format_ratio(price, 2, 5)?));
    }
    if let Some(updated_at) = historical_order.updated_at {
        result.push(format!("updated_at: {}", format_datetime(updated_at)?));
    }
    if let Some(ref conf_settings) = historical_order.conf_settings {
        result.push(format!(
            "conf_settings: {}",
            format_confirmation_settings(conf_settings),
        ));
    }
    Ok(result.join(delimiter))
}